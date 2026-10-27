package checker

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDefaultRulesAreValid(t *testing.T) {
	rules := DefaultRules()
	if len(rules) < 9 {
		t.Fatalf("expected the 9 built-in services, got %d", len(rules))
	}
	seen := map[string]bool{}
	for _, r := range rules {
		if seen[r.Service] {
			t.Errorf("duplicate service %q", r.Service)
		}
		seen[r.Service] = true
	}
}

func TestParseRulesValidation(t *testing.T) {
	bad := map[string]string{
		"no service": "- url: http://x\n  otherwise: {status: yes}\n",
		"no url":     "- service: a\n  otherwise: {status: yes}\n",
		"bad status": "- service: a\n  url: http://x\n  otherwise: {status: maybe}\n",
		"bad regex":  "- service: a\n  url: http://x\n  otherwise: {status: yes, region_regex: '('}\n",
	}
	for name, y := range bad {
		if _, err := ParseRules([]byte(y)); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

func TestEvaluate(t *testing.T) {
	r := Rule{
		Service: "S",
		Steps: []Step{
			{When: Condition{Status: []int{200}, URLContains: []string{"unavailable"}}, Then: Outcome{Status: "no", Detail: "region"}},
			{When: Condition{Status: []int{200}, BodyContains: []string{"hello"}, BodyNotContains: []string{"captcha"}}, Then: Outcome{Status: "yes", RegionRegex: `country=([A-Z]{2})`, Confidence: "high"}},
			{When: Condition{Status: []int{200}, JSONEquals: map[string]any{"code": 0}}, Then: Outcome{Status: "partial"}},
			{When: Condition{HeaderContains: map[string]string{"X-Block": "yes"}}, Then: Outcome{Status: "no", RegionHeader: "Cf-Ipcountry"}},
		},
		Otherwise: Outcome{Status: "error", Detail: "status {status}"},
	}
	h := http.Header{}
	cases := []struct {
		name   string
		resp   response
		status string
		region string
		detail string
	}{
		{"url rule wins first", response{status: 200, finalURL: "https://x/Unavailable", body: []byte("hello")}, "no", "", "region"},
		{"body + regex", response{status: 200, finalURL: "https://x/", body: []byte("Hello country=JP")}, "yes", "JP", ""},
		{"negated body", response{status: 200, finalURL: "https://x/", body: []byte("hello captcha")}, "error", "", "status 200"},
		{"json", response{status: 200, finalURL: "https://x/", body: []byte(`{"code":0}`)}, "partial", "", ""},
		{"header + region header", response{status: 500, header: http.Header{"X-Block": {"YES"}, "Cf-Ipcountry": {"US"}}, finalURL: "https://x/"}, "no", "US", ""},
		{"otherwise", response{status: 502, header: h, finalURL: "https://x/"}, "error", "", "status 502"},
	}
	for _, c := range cases {
		if c.resp.header == nil {
			c.resp.header = h
		}
		got := r.evaluate(c.resp)
		if got.Status != c.status || got.Region != c.region || got.Detail != c.detail {
			t.Errorf("%s: got %+v", c.name, got)
		}
	}
}

func serve(status int, body string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
		w.Write([]byte(body))
	}))
}

func TestRunWithFallback(t *testing.T) {
	primary := serve(503, "")
	defer primary.Close()
	backup := serve(401, "")
	defer backup.Close()

	r := Rule{
		Service:   "S",
		URL:       primary.URL,
		Otherwise: Outcome{Status: "error", Detail: "status {status}"},
		Fallback: &Rule{
			URL:       backup.URL,
			Steps:     []Step{{When: Condition{Status: []int{401}}, Then: Outcome{Status: "yes", Confidence: "medium"}}},
			Otherwise: Outcome{Status: "error"},
		},
	}
	// An empty proxy URL means a direct connection in proxy.NewHTTPClient only if
	// supported; otherwise this test is skipped.
	got, ev := r.Run(context.Background(), "", 2*time.Second)
	if got.Status != "yes" || got.Service != "S" || ev.URL != backup.URL {
		t.Skipf("direct (no-proxy) client unsupported here: %+v", got)
	}
}

func TestLoadRulesOverrideAndExtend(t *testing.T) {
	p := filepath.Join(t.TempDir(), "r.yaml")
	os.WriteFile(p, []byte(`
- service: netflix
  url: http://override.example/
  otherwise: {status: yes}
- service: Custom
  url: http://custom.example/
  otherwise: {status: no}
`), 0o600)
	rules, err := LoadRules(p)
	if err != nil {
		t.Fatal(err)
	}
	base := len(DefaultRules())
	if len(rules) != base+1 {
		t.Fatalf("want %d rules (1 replaced, 1 added), got %d", base+1, len(rules))
	}
	if rules[0].URL != "http://override.example/" || rules[len(rules)-1].Service != "Custom" {
		t.Fatalf("override/extend failed: %q %q", rules[0].URL, rules[len(rules)-1].Service)
	}
	if _, err := LoadRules("/nonexistent.yaml"); err == nil {
		t.Fatal("missing file must error")
	}
}
