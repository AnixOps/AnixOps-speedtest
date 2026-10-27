package checker

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/anixops/speedtest/internal/proxy"
	"gopkg.in/yaml.v3"
)

//go:embed rules.yaml
var defaultRulesYAML []byte

// Rule describes how to test one service; see rules.yaml for the schema.
type Rule struct {
	Service   string            `yaml:"service"`
	URL       string            `yaml:"url"`
	Headers   map[string]string `yaml:"headers"`
	Steps     []Step            `yaml:"steps"`
	Otherwise Outcome           `yaml:"otherwise"`
	Fallback  *Rule             `yaml:"fallback"`
}

// Step is one when/then pair.
type Step struct {
	When Condition `yaml:"when"`
	Then Outcome   `yaml:"then"`
}

// Condition holds AND-ed predicates; empty fields are ignored.
type Condition struct {
	Status          []int             `yaml:"status"`
	URLContains     []string          `yaml:"url_contains"`
	BodyContains    []string          `yaml:"body_contains"`
	BodyNotContains []string          `yaml:"body_not_contains"`
	HeaderContains  map[string]string `yaml:"header_contains"`
	JSONEquals      map[string]any    `yaml:"json_equals"`
}

// Outcome is the verdict a matching step produces.
type Outcome struct {
	Status       string `yaml:"status"`
	Detail       string `yaml:"detail"`
	Region       string `yaml:"region"`
	RegionHeader string `yaml:"region_header"`
	RegionRegex  string `yaml:"region_regex"`
	Confidence   string `yaml:"confidence"`
}

var validStatus = map[string]bool{"yes": true, "no": true, "partial": true, "error": true}

// Validate checks that a rule (and its fallback) is well-formed.
func (r *Rule) Validate() error {
	if r.Service == "" {
		return fmt.Errorf("rule without a service name")
	}
	if r.URL == "" {
		return fmt.Errorf("rule %q: url is required", r.Service)
	}
	check := func(where string, o Outcome) error {
		if !validStatus[o.Status] {
			return fmt.Errorf("rule %q %s: invalid status %q (want yes|no|partial|error)", r.Service, where, o.Status)
		}
		if o.RegionRegex != "" {
			if _, err := regexp.Compile(o.RegionRegex); err != nil {
				return fmt.Errorf("rule %q %s: bad region_regex: %w", r.Service, where, err)
			}
		}
		return nil
	}
	for i, s := range r.Steps {
		if err := check(fmt.Sprintf("step %d", i+1), s.Then); err != nil {
			return err
		}
	}
	if err := check("otherwise", r.Otherwise); err != nil {
		return err
	}
	if r.Fallback != nil {
		fb := *r.Fallback
		fb.Service = r.Service
		return fb.Validate()
	}
	return nil
}

// ParseRules decodes and validates a rules document.
func ParseRules(data []byte) ([]Rule, error) {
	var rules []Rule
	if err := yaml.Unmarshal(data, &rules); err != nil {
		return nil, fmt.Errorf("parse unlock rules: %w", err)
	}
	for i := range rules {
		if err := rules[i].Validate(); err != nil {
			return nil, err
		}
	}
	return rules, nil
}

// DefaultRules returns the built-in rule set.
func DefaultRules() []Rule {
	rules, err := ParseRules(defaultRulesYAML)
	if err != nil {
		panic("built-in unlock rules are invalid: " + err.Error()) // covered by tests
	}
	return rules
}

// LoadRules returns the built-in rules, overridden/extended by the file at path
// (if non-empty): same-named rules are replaced, new ones appended.
func LoadRules(path string) ([]Rule, error) {
	rules := DefaultRules()
	if path == "" {
		return rules, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read unlock rules: %w", err)
	}
	custom, err := ParseRules(data)
	if err != nil {
		return nil, err
	}
	for _, c := range custom {
		replaced := false
		for i := range rules {
			if strings.EqualFold(rules[i].Service, c.Service) {
				rules[i], replaced = c, true
				break
			}
		}
		if !replaced {
			rules = append(rules, c)
		}
	}
	return rules, nil
}

// response is the evaluated view of one HTTP exchange.
type response struct {
	status   int
	finalURL string
	header   http.Header
	body     []byte
}

func (c Condition) matches(r response) bool {
	if len(c.Status) > 0 {
		ok := false
		for _, s := range c.Status {
			ok = ok || s == r.status
		}
		if !ok {
			return false
		}
	}
	if len(c.URLContains) > 0 && !containsAny(strings.ToLower(r.finalURL), c.URLContains) {
		return false
	}
	lowerBody := strings.ToLower(string(r.body))
	if len(c.BodyContains) > 0 && !containsAny(lowerBody, c.BodyContains) {
		return false
	}
	if len(c.BodyNotContains) > 0 && containsAny(lowerBody, c.BodyNotContains) {
		return false
	}
	for h, want := range c.HeaderContains {
		if !strings.Contains(strings.ToLower(r.header.Get(h)), strings.ToLower(want)) {
			return false
		}
	}
	if len(c.JSONEquals) > 0 {
		var doc map[string]any
		if json.Unmarshal(r.body, &doc) != nil {
			return false
		}
		for k, want := range c.JSONEquals {
			if fmt.Sprint(doc[k]) != fmt.Sprint(want) {
				return false
			}
		}
	}
	return true
}

func containsAny(haystack string, needles []string) bool {
	for _, n := range needles {
		if strings.Contains(haystack, strings.ToLower(n)) {
			return true
		}
	}
	return false
}

// evaluate applies the rule's steps to a response.
func (r *Rule) evaluate(resp response) UnlockStatus {
	out := r.Otherwise
	for _, s := range r.Steps {
		if s.When.matches(resp) {
			out = s.Then
			break
		}
	}
	u := UnlockStatus{
		Service:    r.Service,
		Status:     out.Status,
		Detail:     strings.ReplaceAll(out.Detail, "{status}", strconv.Itoa(resp.status)),
		Region:     out.Region,
		Confidence: out.Confidence,
	}
	if u.Region == "" && out.RegionHeader != "" {
		u.Region = resp.header.Get(out.RegionHeader)
	}
	if u.Region == "" && out.RegionRegex != "" {
		if m := regexp.MustCompile(out.RegionRegex).FindSubmatch(resp.body); len(m) > 1 {
			u.Region = string(m[1])
		}
	}
	return u
}

const unlockUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

// Run fetches the rule's URL through the proxy and returns the verdict.
func (r *Rule) Run(ctx context.Context, proxyURL string, timeout time.Duration) (UnlockStatus, Evidence) {
	status, ev := r.runOnce(ctx, proxyURL, timeout)
	if r.Fallback != nil && (status.Status == "error" || status.Status == "no") {
		fb := *r.Fallback
		fb.Service = r.Service
		if s2, ev2 := fb.runOnce(ctx, proxyURL, timeout); s2.Status == "yes" || s2.Status == "no" {
			return s2, ev2
		}
	}
	return status, ev
}

func (r *Rule) runOnce(ctx context.Context, proxyURL string, timeout time.Duration) (UnlockStatus, Evidence) {
	ev := Evidence{Test: r.Service, URL: r.URL, Method: "GET"}
	fail := func(err error) (UnlockStatus, Evidence) {
		ev.RawError = err.Error()
		return UnlockStatus{Service: r.Service, Status: "error", Detail: err.Error(), Confidence: "high"}, ev
	}

	client, err := proxy.NewHTTPClient(proxyURL, timeout)
	if err != nil {
		return fail(err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.URL, nil)
	if err != nil {
		return fail(err)
	}
	req.Header.Set("User-Agent", unlockUA)
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	for k, v := range r.Headers {
		req.Header.Set(k, v)
	}

	started := time.Now()
	resp, err := client.Do(req)
	elapsed := time.Since(started)
	ev.Timing = map[string]float64{"total": float64(elapsed) / float64(time.Millisecond)}
	if err != nil {
		return fail(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))

	ev.StatusCode = resp.StatusCode
	ev.Headers = evidenceHeaders(resp)
	ev.Body = truncateBody(string(body), 1024)
	ev.TLSCert = captureTLSCert(resp)

	final := r.URL
	if resp.Request != nil && resp.Request.URL != nil {
		final = resp.Request.URL.String()
	}
	return r.evaluate(response{status: resp.StatusCode, finalURL: final, header: resp.Header, body: body}), ev
}

// RunUnlockChecks runs every rule concurrently and returns results in rule order.
func RunUnlockChecks(ctx context.Context, proxyURL string, timeout time.Duration, rules []Rule) ([]UnlockStatus, []Evidence) {
	statuses := make([]UnlockStatus, len(rules))
	evidence := make([]Evidence, len(rules))
	var wg sync.WaitGroup
	for i := range rules {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			statuses[i], evidence[i] = rules[i].Run(ctx, proxyURL, timeout)
		}(i)
	}
	wg.Wait()
	return statuses, evidence
}
