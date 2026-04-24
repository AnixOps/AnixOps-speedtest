package checker

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/anixops/speedtest/internal/proxy"
)

// TLSCertInfo holds the leaf certificate details from an HTTPS response.
type TLSCertInfo struct {
	FingerprintSHA256 string `json:"fingerprint_sha256"`
	Issuer            string `json:"issuer,omitempty"`
	Subject           string `json:"subject,omitempty"`
	NotAfter          string `json:"not_after,omitempty"`
}

func certFingerprint(cert *x509.Certificate) string {
	digest := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(digest[:])
}

func captureTLSCert(resp *http.Response) *TLSCertInfo {
	if resp == nil || resp.TLS == nil || len(resp.TLS.PeerCertificates) == 0 {
		return nil
	}
	leaf := resp.TLS.PeerCertificates[0]
	return &TLSCertInfo{
		FingerprintSHA256: certFingerprint(leaf),
		Issuer:            leaf.Issuer.CommonName,
		Subject:           leaf.Subject.CommonName,
		NotAfter:          leaf.NotAfter.UTC().Format(time.RFC3339),
	}
}

// Evidence records raw request/response data for a single test step.
type Evidence struct {
	Test       string            `json:"test"`
	URL        string            `json:"url"`
	Method     string            `json:"method"`
	StatusCode int               `json:"status_code,omitempty"`
	Headers    map[string]string `json:"headers,omitempty"`
	Body       string            `json:"body,omitempty"`
	Timing     map[string]float64 `json:"timing_ms,omitempty"`
	RawError   string            `json:"error,omitempty"`
	TLSCert    *TLSCertInfo      `json:"tls_cert,omitempty"`
}

func evidenceHeaders(resp *http.Response) map[string]string {
	if resp == nil {
		return nil
	}
	h := make(map[string]string)
	for _, key := range []string{"Content-Type", "Content-Length", "Location", "Cf-Ipcountry", "X-Netflix-Country"} {
		if v := resp.Header.Get(key); v != "" {
			h[key] = v
		}
	}
	if len(h) == 0 {
		return nil
	}
	return h
}

func truncateBody(s string, limit int) string {
	if len(s) <= limit {
		return s
	}
	return s[:limit]
}

type UnlockStatus struct {
	Service string `json:"service"`
	Status  string `json:"status"` // "yes", "no", "partial", "error"
	Region  string `json:"region,omitempty"`
	Detail  string `json:"detail,omitempty"`
}

type IPRiskResult struct {
	IP          string  `json:"ip"`
	RiskScore   float64 `json:"risk_score"`
	RiskLevel   string  `json:"risk_level"` // "low", "medium", "high"
	Country     string  `json:"country,omitempty"`
	ISP         string  `json:"isp,omitempty"`
	ProxyType   string  `json:"proxy_type,omitempty"`
}

type DNSRegionResult struct {
	IP      string `json:"ip"`
	Country string `json:"country,omitempty"`
	City    string `json:"city,omitempty"`
	ISP     string `json:"isp,omitempty"`
	DNS     string `json:"dns,omitempty"`
}

type SSHResult struct {
	Port22Open bool   `json:"port_22_open"`
	Detail     string `json:"detail,omitempty"`
}

// --- Streaming unlock checkers ---

func CheckNetflix(ctx context.Context, proxyURL string, timeout time.Duration) (UnlockStatus, Evidence) {
	return checkStreaming(ctx, proxyURL, timeout, "Netflix", "https://www.netflix.com/title/80018499", extractNetflix)
}

func CheckYouTube(ctx context.Context, proxyURL string, timeout time.Duration) (UnlockStatus, Evidence) {
	return checkStreaming(ctx, proxyURL, timeout, "YouTube Premium", "https://www.youtube.com/premium", extractYouTube)
}

func CheckDisneyPlus(ctx context.Context, proxyURL string, timeout time.Duration) (UnlockStatus, Evidence) {
	s, ev1 := checkStreaming(ctx, proxyURL, timeout, "Disney+", "https://www.disneyplus.com", func(resp *http.Response, body []byte) UnlockStatus {
		result := UnlockStatus{Service: "Disney+"}
		if resp.StatusCode == 200 {
			bodyStr := string(body)
			if strings.Contains(bodyStr, "disney") || strings.Contains(bodyStr, "Disney") {
				result.Status = "yes"
			} else {
				result.Status = "partial"
				result.Detail = "page loaded but content unexpected"
			}
		} else if resp.StatusCode == 403 {
			result.Status = "no"
			result.Detail = "blocked by Disney+"
		} else if resp.StatusCode == 301 || resp.StatusCode == 302 {
			loc := resp.Header.Get("Location")
			if strings.Contains(loc, "unavailable") || strings.Contains(loc, "not-available") {
				result.Status = "no"
				result.Detail = "region not supported"
			} else {
				result.Status = "yes"
			}
		} else {
			result.Status = "error"
			result.Detail = fmt.Sprintf("status %d", resp.StatusCode)
		}
		return result
	})

	// If streaming check failed, try API as fallback
	if s.Status == "error" || s.Status == "no" {
		s2, ev2 := checkStreaming(ctx, proxyURL, timeout, "Disney+", "https://disney.api.edge.bamgrid.com/devices", func(resp *http.Response, body []byte) UnlockStatus {
			result := UnlockStatus{Service: "Disney+"}
			if resp.StatusCode == 200 || resp.StatusCode == 201 {
				result.Status = "yes"
			} else if resp.StatusCode == 401 {
				result.Status = "yes"
				result.Detail = "accessible (API returns content)"
			} else if resp.StatusCode == 403 {
				result.Status = "no"
			} else {
				result.Status = "error"
				result.Detail = fmt.Sprintf("status %d", resp.StatusCode)
			}
			return result
		})
		if s2.Status == "yes" || s2.Status == "no" {
			return s2, ev2
		}
	}

	return s, ev1
}

func CheckBilibili(ctx context.Context, proxyURL string, timeout time.Duration) (UnlockStatus, Evidence) {
	return checkStreaming(ctx, proxyURL, timeout, "Bilibili", "https://api.bilibili.com/pgc/player/web/playurl?avid=2&cid=3&qn=0", extractBilibili)
}

func CheckOpenAI(ctx context.Context, proxyURL string, timeout time.Duration) (UnlockStatus, Evidence) {
	return checkStreaming(ctx, proxyURL, timeout, "OpenAI", "https://chat.openai.com/", extractOpenAI)
}

func CheckClaude(ctx context.Context, proxyURL string, timeout time.Duration) (UnlockStatus, Evidence) {
	return checkStreaming(ctx, proxyURL, timeout, "Claude", "https://claude.ai/", extractClaude)
}

func CheckSpotify(ctx context.Context, proxyURL string, timeout time.Duration) (UnlockStatus, Evidence) {
	return checkStreaming(ctx, proxyURL, timeout, "Spotify", "https://www.spotify.com/", extractSpotify)
}

func CheckTiktok(ctx context.Context, proxyURL string, timeout time.Duration) (UnlockStatus, Evidence) {
	return checkStreaming(ctx, proxyURL, timeout, "Tiktok", "https://www.tiktok.com/", extractTiktok)
}

func CheckWikipedia(ctx context.Context, proxyURL string, timeout time.Duration) (UnlockStatus, Evidence) {
	return checkStreaming(ctx, proxyURL, timeout, "Wikipedia", "https://zh.wikipedia.org/", extractWikipedia)
}

func checkStreaming(ctx context.Context, proxyURL string, timeout time.Duration, service, url string, extract func(*http.Response, []byte) UnlockStatus) (UnlockStatus, Evidence) {
	client, err := proxy.NewHTTPClient(proxyURL, timeout)
	if err != nil {
		ev := Evidence{Test: service, URL: url, Method: "GET", RawError: err.Error()}
		return UnlockStatus{Service: service, Status: "error", Detail: err.Error()}, ev
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		ev := Evidence{Test: service, URL: url, Method: "GET", RawError: err.Error()}
		return UnlockStatus{Service: service, Status: "error", Detail: err.Error()}, ev
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")

	// Disney+ requires specific headers for device registration
	if service == "Disney+" {
		req.Header.Set("Accept", "application/json; charset=utf-8")
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer ZGlzbmV5JmJyb3dzZXImMS4wLjA.Cu56AgSfBTDag5NiRA81oLHkDZfu5L3CKadnefEAYB4")
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
	}

	started := time.Now()
	resp, err := client.Do(req)
	elapsed := time.Since(started)
	if err != nil {
		ev := Evidence{Test: service, URL: url, Method: "GET", Timing: map[string]float64{"total": float64(elapsed) / float64(time.Millisecond)}, RawError: err.Error()}
		return UnlockStatus{Service: service, Status: "error", Detail: err.Error()}, ev
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	status := extract(resp, body)

	ev := Evidence{
		Test:       service,
		URL:        url,
		Method:     "GET",
		StatusCode: resp.StatusCode,
		Headers:    evidenceHeaders(resp),
		Body:       truncateBody(string(body), 1024),
		Timing:     map[string]float64{"total": float64(elapsed) / float64(time.Millisecond)},
		TLSCert:    captureTLSCert(resp),
	}
	return status, ev
}

func extractNetflix(resp *http.Response, body []byte) UnlockStatus {
	s := UnlockStatus{Service: "Netflix"}
	if resp.StatusCode == 200 || resp.StatusCode == 301 || resp.StatusCode == 302 {
		location := resp.Header.Get("Location")
		if strings.Contains(location, "login") || strings.Contains(location, "title") || resp.StatusCode == 200 {
			s.Status = "yes"
			bodyStr := string(body)
			if idx := strings.Index(bodyStr, `"currentCountry"`); idx != -1 {
				if end := strings.Index(bodyStr[idx:], `"}`); end != -1 {
					fragment := bodyStr[idx : idx+end+1]
					if codeIdx := strings.Index(fragment, `"`); codeIdx != -1 {
						s.Region = fragment[codeIdx+1 : len(fragment)-1]
					}
				}
			}
		} else {
			s.Status = "no"
		}
	} else if resp.StatusCode == 403 {
		s.Status = "no"
	} else {
		s.Status = "error"
		s.Detail = fmt.Sprintf("status %d", resp.StatusCode)
	}
	return s
}

func extractYouTube(resp *http.Response, body []byte) UnlockStatus {
	s := UnlockStatus{Service: "YouTube Premium"}
	if resp.StatusCode == 200 {
		bodyStr := string(body)
		if strings.Contains(bodyStr, "Premium") || strings.Contains(bodyStr, "premium") {
			s.Status = "yes"
			if glIdx := strings.Index(bodyStr, `"GL"`); glIdx != -1 {
				frag := bodyStr[glIdx:]
				if codeStart := strings.Index(frag, `"`); codeStart != -1 {
					remaining := frag[codeStart+1:]
					if codeEnd := strings.Index(remaining, `"`); codeEnd != -1 {
						s.Region = remaining[:codeEnd]
					}
				}
			}
		} else {
			s.Status = "partial"
			s.Detail = "accessible but Premium info not found"
		}
	} else {
		s.Status = "no"
	}
	return s
}

func extractBilibili(resp *http.Response, body []byte) UnlockStatus {
	s := UnlockStatus{Service: "Bilibili"}
	if resp.StatusCode == 200 {
		var result struct {
			Code int `json:"code"`
		}
		if err := json.Unmarshal(body, &result); err == nil {
			if result.Code == 0 {
				s.Status = "yes"
				s.Region = "CN"
			} else {
				s.Status = "no"
				s.Detail = fmt.Sprintf("code=%d", result.Code)
			}
		} else {
			s.Status = "partial"
		}
	} else {
		s.Status = "no"
	}
	return s
}

func extractOpenAI(resp *http.Response, body []byte) UnlockStatus {
	s := UnlockStatus{Service: "OpenAI"}
	if resp.StatusCode == 200 {
		s.Status = "yes"
		if cf := resp.Header.Get("Cf-Ipcountry"); cf != "" {
			s.Region = cf
		}
	} else if resp.StatusCode == 403 {
		bodyStr := string(body)
		if strings.Contains(bodyStr, "unsupported_country") || strings.Contains(strings.ToLower(bodyStr), "not available") {
			s.Status = "no"
		} else {
			s.Status = "no"
		}
	} else {
		s.Status = "error"
		s.Detail = fmt.Sprintf("status %d", resp.StatusCode)
	}
	return s
}

func extractClaude(resp *http.Response, body []byte) UnlockStatus {
	s := UnlockStatus{Service: "Claude"}
	if resp.StatusCode == 200 {
		s.Status = "yes"
	} else if resp.StatusCode == 403 {
		s.Status = "no"
	} else {
		s.Status = "error"
		s.Detail = fmt.Sprintf("status %d", resp.StatusCode)
	}
	return s
}

func extractSpotify(resp *http.Response, body []byte) UnlockStatus {
	s := UnlockStatus{Service: "Spotify"}
	if resp.StatusCode == 200 {
		s.Status = "yes"
	} else {
		s.Status = "no"
	}
	return s
}

func extractTiktok(resp *http.Response, body []byte) UnlockStatus {
	s := UnlockStatus{Service: "Tiktok"}
	if resp.StatusCode == 200 {
		s.Status = "yes"
	} else {
		s.Status = "no"
	}
	return s
}

func extractWikipedia(resp *http.Response, body []byte) UnlockStatus {
	s := UnlockStatus{Service: "Wikipedia"}
	if resp.StatusCode == 200 {
		s.Status = "yes"
	} else if resp.StatusCode == 403 {
		s.Status = "no"
	} else {
		s.Status = "error"
		s.Detail = fmt.Sprintf("status %d", resp.StatusCode)
	}
	return s
}

// --- IP Risk checker ---

func CheckIPRisk(ctx context.Context, proxyURL string, timeout time.Duration) (IPRiskResult, []Evidence) {
	var evidence []Evidence
	client, err := proxy.NewHTTPClient(proxyURL, timeout)
	if err != nil {
		return IPRiskResult{RiskLevel: "error"}, evidence
	}

	// Try ipinfo.io first
	result, ev1 := fetchIPInfo(client, ctx, timeout, "https://ipinfo.io/json", func(body []byte) IPRiskResult {
		var data struct {
			IP      string `json:"ip"`
			City    string `json:"city"`
			Region  string `json:"region"`
			Country string `json:"country"`
			Org     string `json:"org"`
			Loc     string `json:"loc"`
		}
		if err := json.Unmarshal(body, &data); err != nil {
			return IPRiskResult{}
		}
		r := IPRiskResult{
			IP:      data.IP,
			Country: data.Country,
			ISP:     data.Org,
		}
		if data.Org != "" && (strings.Contains(strings.ToLower(data.Org), "hosting") ||
			strings.Contains(strings.ToLower(data.Org), "datacenter") ||
			strings.Contains(strings.ToLower(data.Org), "cloud")) {
			r.RiskScore = 75
			r.RiskLevel = "high"
			r.ProxyType = "proxy/datacenter"
		}
		return r
	})
	if ev1.Test != "" {
		evidence = append(evidence, ev1)
	}
	if result.IP != "" {
		// Cross-check with ip-api.com for proxy/hosting detection
		url2 := fmt.Sprintf("http://ip-api.com/json/%s?fields=status,country,isp,proxy,hosting", result.IP)
		req2, err := http.NewRequestWithContext(ctx, http.MethodGet, url2, nil)
		started2 := time.Now()
		if err == nil {
			resp2, err2 := client.Do(req2)
			elapsed2 := time.Since(started2)
			if err2 == nil {
				defer resp2.Body.Close()
				body2, _ := io.ReadAll(io.LimitReader(resp2.Body, 64*1024))
				var ipData struct {
					Status  string `json:"status"`
					Country string `json:"country"`
					ISP     string `json:"isp"`
					Proxy   bool   `json:"proxy"`
					Hosting bool   `json:"hosting"`
				}
				if json.Unmarshal(body2, &ipData) == nil && ipData.Status == "success" {
					if ipData.Proxy || ipData.Hosting {
						result.RiskScore = 75
						result.RiskLevel = "high"
						result.ProxyType = "proxy/datacenter"
					} else if result.RiskLevel == "" {
						result.RiskScore = 15
						result.RiskLevel = "low"
					}
					if result.Country == "" {
						result.Country = ipData.Country
					}
					if result.ISP == "" {
						result.ISP = ipData.ISP
					}
				}
				evidence = append(evidence, Evidence{
					Test:       "ip_risk_check",
					URL:        url2,
					Method:     "GET",
					StatusCode: resp2.StatusCode,
					Body:       truncateBody(string(body2), 1024),
					Timing:     map[string]float64{"total": float64(elapsed2) / float64(time.Millisecond)},
				})
			}
		}
		if result.RiskLevel == "" {
			result.RiskScore = 30
			result.RiskLevel = "medium"
		}
		return result, evidence
	}

	// Fallback: ip-api.com direct lookup
	result2, ev2 := fetchIPRiskWithEvidence(client, ctx, timeout, "http://ip-api.com/json/?fields=status,country,isp,proxy,hosting")
	if ev2.Test != "" {
		evidence = append(evidence, ev2)
	}
	if result2.RiskLevel != "" {
		result = result2
	}

	if result.RiskLevel == "" {
		result.RiskScore = 50
		result.RiskLevel = "medium"
	}
	return result, evidence
}

func fetchIPRiskWithEvidence(client *http.Client, ctx context.Context, timeout time.Duration, url string) (IPRiskResult, Evidence) {
	started := time.Now()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return IPRiskResult{}, Evidence{Test: "ip_risk", URL: url, Method: "GET", RawError: err.Error()}
	}
	req.Header.Set("User-Agent", "Mozilla/5.0")

	resp, err := client.Do(req)
	elapsed := time.Since(started)
	if err != nil {
		return IPRiskResult{}, Evidence{Test: "ip_risk", URL: url, Method: "GET", Timing: map[string]float64{"total": float64(elapsed) / float64(time.Millisecond)}, RawError: err.Error()}
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if resp.StatusCode != 200 {
		return IPRiskResult{}, Evidence{Test: "ip_risk", URL: url, Method: "GET", StatusCode: resp.StatusCode, Body: truncateBody(string(body), 1024)}
	}

	var data struct {
		Status  string `json:"status"`
		Country string `json:"country"`
		ISP     string `json:"isp"`
		Proxy   bool   `json:"proxy"`
		Hosting bool   `json:"hosting"`
		IP      string `json:"query"`
	}
	if json.Unmarshal(body, &data) != nil || data.Status != "success" {
		return IPRiskResult{}, Evidence{Test: "ip_risk", URL: url, Method: "GET", StatusCode: resp.StatusCode, Body: truncateBody(string(body), 512)}
	}

	r := IPRiskResult{Country: data.Country, ISP: data.ISP, IP: data.IP}
	if data.Proxy || data.Hosting {
		r.RiskScore = 75
		r.RiskLevel = "high"
		r.ProxyType = "proxy/datacenter"
	} else {
		r.RiskScore = 15
		r.RiskLevel = "low"
	}

	return r, Evidence{
		Test:       "ip_risk",
		URL:        url,
		Method:     "GET",
		StatusCode: resp.StatusCode,
		Body:       truncateBody(string(body), 1024),
		Timing:     map[string]float64{"total": float64(elapsed) / float64(time.Millisecond)},
	}
}

func fetchIPInfo(client *http.Client, ctx context.Context, timeout time.Duration, url string, parse func([]byte) IPRiskResult) (IPRiskResult, Evidence) {
	started := time.Now()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return IPRiskResult{}, Evidence{Test: "ip_info", URL: url, Method: "GET", RawError: err.Error()}
	}
	req.Header.Set("User-Agent", "Mozilla/5.0")

	resp, err := client.Do(req)
	elapsed := time.Since(started)
	if err != nil {
		return IPRiskResult{}, Evidence{Test: "ip_info", URL: url, Method: "GET", Timing: map[string]float64{"total": float64(elapsed) / float64(time.Millisecond)}, RawError: err.Error()}
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if resp.StatusCode != 200 {
		return IPRiskResult{}, Evidence{Test: "ip_info", URL: url, Method: "GET", StatusCode: resp.StatusCode, Body: truncateBody(string(body), 512), Timing: map[string]float64{"total": float64(elapsed) / float64(time.Millisecond)}, TLSCert: captureTLSCert(resp)}
	}

	result := parse(body)
	return result, Evidence{
		Test:       "ip_info",
		URL:        url,
		Method:     "GET",
		StatusCode: resp.StatusCode,
		Body:       truncateBody(string(body), 1024),
		Timing:     map[string]float64{"total": float64(elapsed) / float64(time.Millisecond)},
		TLSCert:    captureTLSCert(resp),
	}
}

// --- DNS Region ---

func CheckDNSRegion(ctx context.Context, proxyURL string, timeout time.Duration) (DNSRegionResult, []Evidence) {
	var evidence []Evidence
	client, err := proxy.NewHTTPClient(proxyURL, timeout)
	if err != nil {
		return DNSRegionResult{}, evidence
	}

	// Try ipinfo.io
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://ipinfo.io/json/", nil)
	if err != nil {
		return DNSRegionResult{}, evidence
	}
	req.Header.Set("User-Agent", "Mozilla/5.0")

	started := time.Now()
	resp, err := client.Do(req)
	elapsed := time.Since(started)
	if err != nil {
		// Fallback: ip-api.com
		req2, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://ip-api.com/json/?fields=status,country,city,isp", nil)
		if req2 == nil {
			return DNSRegionResult{}, evidence
		}
		req2.Header.Set("User-Agent", "Mozilla/5.0")
		resp2, err2 := client.Do(req2)
		if err2 != nil {
			return DNSRegionResult{}, evidence
		}
		defer resp2.Body.Close()
		body2, _ := io.ReadAll(io.LimitReader(resp2.Body, 64*1024))
		var data2 struct {
			Status  string `json:"status"`
			Country string `json:"country"`
			City    string `json:"city"`
			ISP     string `json:"isp"`
		}
		if json.Unmarshal(body2, &data2) == nil && data2.Status == "success" {
			return DNSRegionResult{
				IP:      "",
				Country: data2.Country,
				City:    data2.City,
				ISP:     data2.ISP,
			}, evidence
		}
		return DNSRegionResult{}, evidence
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))

	var data struct {
		IP      string `json:"ip"`
		Country string `json:"country"`
		City    string `json:"city"`
		Region  string `json:"region"`
		Org     string `json:"org"`
	}
	if err := json.Unmarshal(body, &data); err != nil {
		return DNSRegionResult{}, []Evidence{{
			Test:       "dns_region",
			URL:        "https://ipinfo.io/json/",
			Method:     "GET",
			StatusCode: resp.StatusCode,
			Body:       truncateBody(string(body), 512),
			Timing:     map[string]float64{"total": float64(elapsed) / float64(time.Millisecond)},
			TLSCert:    captureTLSCert(resp),
		}}
	}

	evidence = append(evidence, Evidence{
		Test:       "dns_region",
		URL:        "https://ipinfo.io/json/",
		Method:     "GET",
		StatusCode: resp.StatusCode,
		Body:       truncateBody(string(body), 1024),
		Timing:     map[string]float64{"total": float64(elapsed) / float64(time.Millisecond)},
		TLSCert:    captureTLSCert(resp),
	})

	return DNSRegionResult{
		IP:      data.IP,
		Country: data.Country,
		City:    data.City,
		ISP:     data.Org,
	}, evidence
}

// --- SSH port check ---

func CheckSSH(ctx context.Context, proxyURL string, timeout time.Duration) SSHResult {
	target := "1.1.1.1:22"
	if proxyURL == "" {
		dialer := &net.Dialer{Timeout: timeout}
		conn, err := dialer.DialContext(ctx, "tcp", target)
		if err == nil {
			conn.Close()
			return SSHResult{Port22Open: true}
		}
		return SSHResult{Port22Open: false}
	}

	conn, err := proxy.DialTCP(ctx, proxyURL, target, timeout)
	if err == nil {
		conn.Close()
		return SSHResult{Port22Open: true}
	}
	return SSHResult{Port22Open: false, Detail: err.Error()}
}
