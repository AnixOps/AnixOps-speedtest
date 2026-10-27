package checker

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/anixops/speedtest/internal/proxy"
)

// AllowPlainHTTPGeoIPEnv enables the plain-HTTP ip-api.com provider as a last
// resort. Its free tier has no HTTPS, so the answer can be forged on the path
// between the proxy exit and the API; it is therefore opt-in.
const AllowPlainHTTPGeoIPEnv = "SPEEDTEST_ALLOW_HTTP_GEOIP"

const ipRiskCacheTTL = 30 * time.Minute

// ipRiskCache de-duplicates lookups: many nodes share one exit IP, and the free
// GeoIP APIs rate-limit aggressively.
var ipRiskCache = struct {
	sync.Mutex
	m map[string]cachedRisk
}{m: map[string]cachedRisk{}}

type cachedRisk struct {
	res     IPRiskResult
	expires time.Time
}

func cacheGet(ip string) (IPRiskResult, bool) {
	ipRiskCache.Lock()
	defer ipRiskCache.Unlock()
	c, ok := ipRiskCache.m[ip]
	if !ok || time.Now().After(c.expires) {
		delete(ipRiskCache.m, ip)
		return IPRiskResult{}, false
	}
	return c.res, true
}

func cachePut(ip string, r IPRiskResult) {
	ipRiskCache.Lock()
	defer ipRiskCache.Unlock()
	ipRiskCache.m[ip] = cachedRisk{res: r, expires: time.Now().Add(ipRiskCacheTTL)}
}

// rateGate spaces calls to a provider at least interval apart.
type rateGate struct {
	mu       sync.Mutex
	next     time.Time
	interval time.Duration
}

func (g *rateGate) wait(ctx context.Context) error {
	g.mu.Lock()
	now := time.Now()
	at := g.next
	if at.Before(now) {
		at = now
	}
	g.next = at.Add(g.interval)
	g.mu.Unlock()
	select {
	case <-time.After(time.Until(at)):
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// ipFlags is the provider-neutral view of a GeoIP/reputation answer.
type ipFlags struct {
	Country    string
	ISP        string
	Datacenter bool
	Proxy      bool
	VPN        bool
	Tor        bool
	Abuser     bool
}

// scoreIPRisk maps reputation flags to a 0-100 score, level and proxy type.
func scoreIPRisk(f ipFlags) (score float64, level, proxyType string) {
	switch {
	case f.Tor:
		return 95, "high", "tor"
	case f.VPN:
		return 80, "high", "vpn"
	case f.Proxy:
		return 75, "high", "proxy"
	case f.Datacenter:
		return 70, "high", "datacenter"
	case f.Abuser:
		return 60, "medium", ""
	}
	return 15, "low", ""
}

func (f ipFlags) result(ip string) IPRiskResult {
	score, level, ptype := scoreIPRisk(f)
	return IPRiskResult{IP: ip, RiskScore: score, RiskLevel: level, ProxyType: ptype, Country: f.Country, ISP: f.ISP}
}

type riskProvider struct {
	name  string
	url   func(ip string) string // ip is empty for "my own address"
	parse func(body []byte) (ip string, f ipFlags, ok bool)
	gate  *rateGate
}

var ipapiIs = riskProvider{
	name: "ipapi.is",
	url: func(ip string) string {
		if ip == "" {
			return "https://api.ipapi.is/"
		}
		return "https://api.ipapi.is/?q=" + ip
	},
	parse: parseIPAPIIs,
}

var ipAPICom = riskProvider{
	name: "ip-api.com",
	url: func(ip string) string {
		return "http://ip-api.com/json/" + ip + "?fields=status,country,isp,proxy,hosting,query"
	},
	parse: parseIPAPICom,
	gate:  &rateGate{interval: 1500 * time.Millisecond}, // free tier: 45 req/min
}

func parseIPAPIIs(body []byte) (string, ipFlags, bool) {
	var d struct {
		IP           string `json:"ip"`
		IsDatacenter bool   `json:"is_datacenter"`
		IsProxy      bool   `json:"is_proxy"`
		IsVPN        bool   `json:"is_vpn"`
		IsTor        bool   `json:"is_tor"`
		IsAbuser     bool   `json:"is_abuser"`
		Company      struct {
			Name string `json:"name"`
			Type string `json:"type"`
		} `json:"company"`
		Location struct {
			Country string `json:"country"`
		} `json:"location"`
	}
	if json.Unmarshal(body, &d) != nil || d.IP == "" {
		return "", ipFlags{}, false
	}
	return d.IP, ipFlags{
		Country:    d.Location.Country,
		ISP:        d.Company.Name,
		Datacenter: d.IsDatacenter || d.Company.Type == "hosting",
		Proxy:      d.IsProxy,
		VPN:        d.IsVPN,
		Tor:        d.IsTor,
		Abuser:     d.IsAbuser,
	}, true
}

func parseIPAPICom(body []byte) (string, ipFlags, bool) {
	var d struct {
		Status  string `json:"status"`
		Country string `json:"country"`
		ISP     string `json:"isp"`
		Proxy   bool   `json:"proxy"`
		Hosting bool   `json:"hosting"`
		Query   string `json:"query"`
	}
	if json.Unmarshal(body, &d) != nil || d.Status != "success" {
		return "", ipFlags{}, false
	}
	return d.Query, ipFlags{Country: d.Country, ISP: d.ISP, Proxy: d.Proxy, Datacenter: d.Hosting}, true
}

func (p riskProvider) lookup(ctx context.Context, client *http.Client, ip string) (string, ipFlags, Evidence, bool) {
	url := p.url(ip)
	ev := Evidence{Test: "ip_risk", URL: url, Method: "GET"}
	if p.gate != nil {
		if err := p.gate.wait(ctx); err != nil {
			ev.RawError = err.Error()
			return "", ipFlags{}, ev, false
		}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		ev.RawError = err.Error()
		return "", ipFlags{}, ev, false
	}
	req.Header.Set("User-Agent", "Mozilla/5.0")
	started := time.Now()
	resp, err := client.Do(req)
	ev.Timing = map[string]float64{"total": float64(time.Since(started)) / float64(time.Millisecond)}
	if err != nil {
		ev.RawError = err.Error()
		return "", ipFlags{}, ev, false
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	ev.StatusCode = resp.StatusCode
	ev.Body = truncateBody(string(body), 1024)
	ev.TLSCert = captureTLSCert(resp)
	if resp.StatusCode != http.StatusOK {
		return "", ipFlags{}, ev, false
	}
	gotIP, flags, ok := p.parse(body)
	return gotIP, flags, ev, ok
}

// CheckIPRisk resolves the proxy's exit IP and scores its reputation. Providers
// are tried in order over HTTPS; plain-HTTP ip-api.com is used only when opted in.
func CheckIPRisk(ctx context.Context, proxyURL string, timeout time.Duration) (IPRiskResult, []Evidence) {
	var evidence []Evidence
	client, err := proxy.NewHTTPClient(proxyURL, timeout)
	if err != nil {
		return IPRiskResult{RiskLevel: "error"}, evidence
	}

	// Step 1: discover the exit IP (cheap, HTTPS).
	base, ev := fetchIPInfo(client, ctx, timeout, "https://ipinfo.io/json", parseIPInfoOrg)
	if ev.Test != "" {
		evidence = append(evidence, ev)
	}

	// Step 2: reputation lookup, de-duplicated per exit IP.
	if base.IP != "" {
		if cached, hit := cacheGet(base.IP); hit {
			return cached, evidence
		}
	}
	providers := []riskProvider{ipapiIs}
	if os.Getenv(AllowPlainHTTPGeoIPEnv) == "1" {
		providers = append(providers, ipAPICom)
	}
	for _, p := range providers {
		ip, flags, pev, ok := p.lookup(ctx, client, base.IP)
		evidence = append(evidence, pev)
		if !ok {
			continue
		}
		res := flags.result(ip)
		cachePut(ip, res)
		return res, evidence
	}

	// No reputation provider answered: keep ipinfo's coarse hosting-keyword
	// heuristic, and report "medium" when even that found nothing.
	if base.RiskLevel == "" {
		base.RiskScore, base.RiskLevel = 30, "medium"
	}
	return base, evidence
}

func parseIPInfoOrg(body []byte) IPRiskResult {
	var d struct {
		IP      string `json:"ip"`
		Country string `json:"country"`
		Org     string `json:"org"`
	}
	if json.Unmarshal(body, &d) != nil {
		return IPRiskResult{}
	}
	r := IPRiskResult{IP: d.IP, Country: d.Country, ISP: d.Org}
	org := strings.ToLower(d.Org)
	if strings.Contains(org, "hosting") || strings.Contains(org, "datacenter") || strings.Contains(org, "cloud") {
		r.RiskScore, r.RiskLevel, r.ProxyType = 70, "high", "datacenter"
	}
	return r
}
