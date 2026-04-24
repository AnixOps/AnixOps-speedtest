package topo

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
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
	Body       string            `json:"body,omitempty"`
	Timing     map[string]float64 `json:"timing_ms,omitempty"`
	RawError   string            `json:"error,omitempty"`
	TLSCert    *TLSCertInfo      `json:"tls_cert,omitempty"`
}

func truncateBody(s string, limit int) string {
	if len(s) <= limit {
		return s
	}
	return s[:limit]
}

type TopologyResult struct {
	EntryIP    string `json:"entry_ip"`
	EntryCountry string `json:"entry_country,omitempty"`
	ExitIP     string `json:"exit_ip"`
	ExitCountry  string `json:"exit_country,omitempty"`
	ExitISP    string `json:"exit_isp,omitempty"`
	Match      bool   `json:"match"`
}

func Analyze(ctx context.Context, proxyURL string, directTimeout, proxyTimeout time.Duration) (TopologyResult, []Evidence) {
	var evidence []Evidence
	result := TopologyResult{}

	// Direct IP (origin)
	directClient := &http.Client{Timeout: directTimeout}
	directReq, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://ipinfo.io/json/", nil)
	directReq.Header.Set("User-Agent", "Mozilla/5.0")
	started := time.Now()
	if resp, err := directClient.Do(directReq); err == nil {
		defer resp.Body.Close()
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
		elapsed := time.Since(started)
		var data struct {
			IP      string `json:"ip"`
			Country string `json:"country"`
		}
		if json.Unmarshal(body, &data) == nil {
			result.EntryIP = data.IP
			result.EntryCountry = data.Country
		}
		evidence = append(evidence, Evidence{
			Test:       "topology_entry",
			URL:        "https://ipinfo.io/json/",
			Method:     "GET",
			StatusCode: resp.StatusCode,
			Body:       truncateBody(string(body), 1024),
			Timing:     map[string]float64{"total": float64(elapsed) / float64(time.Millisecond)},
			TLSCert:    captureTLSCert(resp),
		})
	} else {
		elapsed := time.Since(started)
		evidence = append(evidence, Evidence{
			Test:     "topology_entry",
			URL:      "https://ipinfo.io/json/",
			Method:   "GET",
			Timing:   map[string]float64{"total": float64(elapsed) / float64(time.Millisecond)},
			RawError: err.Error(),
		})
	}

	// Proxied IP (exit)
	proxyClient, err := proxy.NewHTTPClient(proxyURL, proxyTimeout)
	if err != nil {
		return result, evidence
	}

	proxyReq, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://ipinfo.io/json/", nil)
	proxyReq.Header.Set("User-Agent", "Mozilla/5.0")
	started = time.Now()
	if resp, err := proxyClient.Do(proxyReq); err == nil {
		defer resp.Body.Close()
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
		elapsed := time.Since(started)
		var data struct {
			IP      string `json:"ip"`
			Country string `json:"country"`
			Org     string `json:"org"`
		}
		if json.Unmarshal(body, &data) == nil {
			result.ExitIP = data.IP
			result.ExitCountry = data.Country
			result.ExitISP = data.Org
		}
		evidence = append(evidence, Evidence{
			Test:       "topology_exit",
			URL:        "https://ipinfo.io/json/",
			Method:     "GET",
			StatusCode: resp.StatusCode,
			Body:       truncateBody(string(body), 1024),
			Timing:     map[string]float64{"total": float64(elapsed) / float64(time.Millisecond)},
			TLSCert:    captureTLSCert(resp),
		})
	} else {
		elapsed := time.Since(started)
		evidence = append(evidence, Evidence{
			Test:     "topology_exit",
			URL:      "https://ipinfo.io/json/",
			Method:   "GET",
			Timing:   map[string]float64{"total": float64(elapsed) / float64(time.Millisecond)},
			RawError: err.Error(),
		})
	}

	if result.EntryIP != "" && result.ExitIP != "" {
		result.Match = strings.EqualFold(result.EntryCountry, result.ExitCountry)
	}

	return result, evidence
}

func FormatTopo(t TopologyResult) string {
	if t.ExitIP == "" {
		return "N/A"
	}
	entry := t.EntryIP
	if t.EntryCountry != "" {
		entry = fmt.Sprintf("%s (%s)", t.EntryIP, t.EntryCountry)
	}
	exit := t.ExitIP
	if t.ExitCountry != "" {
		exit = fmt.Sprintf("%s (%s)", t.ExitIP, t.ExitCountry)
	}
	if t.EntryIP == "" {
		return fmt.Sprintf("Exit: %s", exit)
	}
	match := "different"
	if t.Match {
		match = "same"
	}
	return fmt.Sprintf("Entry: %s -> Exit: %s [%s region]", entry, exit, match)
}
