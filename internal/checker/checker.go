package checker

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
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
	Test       string             `json:"test"`
	URL        string             `json:"url"`
	Method     string             `json:"method"`
	StatusCode int                `json:"status_code,omitempty"`
	Headers    map[string]string  `json:"headers,omitempty"`
	Body       string             `json:"body,omitempty"`
	Timing     map[string]float64 `json:"timing_ms,omitempty"`
	RawError   string             `json:"error,omitempty"`
	TLSCert    *TLSCertInfo       `json:"tls_cert,omitempty"`
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
	// Confidence is how much the matching rule trusts its verdict: high|medium|low.
	Confidence string `json:"confidence,omitempty"`
}

type IPRiskResult struct {
	IP        string  `json:"ip"`
	RiskScore float64 `json:"risk_score"`
	RiskLevel string  `json:"risk_level"` // "low", "medium", "high"
	Country   string  `json:"country,omitempty"`
	ISP       string  `json:"isp,omitempty"`
	ProxyType string  `json:"proxy_type,omitempty"`
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

// --- IP Risk checker ---

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
		// Fallback: ipapi.is (HTTPS)
		ip, f, ev, ok := ipapiIs.lookup(ctx, client, "")
		evidence = append(evidence, ev)
		if !ok {
			return DNSRegionResult{}, evidence
		}
		return DNSRegionResult{IP: ip, Country: f.Country, ISP: f.ISP}, evidence
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
