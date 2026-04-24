package probe

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/anixops/speedtest/internal/checker"
	"github.com/anixops/speedtest/internal/clash"
	"github.com/anixops/speedtest/internal/mihomo"
	"github.com/anixops/speedtest/internal/proxy"
	"github.com/anixops/speedtest/internal/topo"
	"github.com/anixops/speedtest/internal/xray"
)

type Kernel string

const (
	KernelXray   Kernel = "xray"
	KernelMihomo Kernel = "mihomo"
)

type Config struct {
	Kernel        Kernel
	Timeout       time.Duration
	DownloadSize  int64
	SkipLatency   bool
	SkipSpeed     bool
	SkipUnlock    bool
	SkipTopo      bool
	SkipIPRisk    bool
	SkipDNS       bool
	SkipSSH       bool
	BinDir        string
}

type NodeResult struct {
	Index    int                    `json:"index"`
	Name     string                 `json:"name"`
	Type     string                 `json:"type"`
	Server   string                 `json:"server"`
	Port     int                    `json:"port"`
	Latency  *LatencyResult         `json:"latency,omitempty"`
	Speed    *SpeedResult           `json:"speed,omitempty"`
	Unlocks  []checker.UnlockStatus `json:"unlocks,omitempty"`
	IPRisk   *checker.IPRiskResult  `json:"ip_risk,omitempty"`
	DNS      *checker.DNSRegionResult `json:"dns,omitempty"`
	SSH      *checker.SSHResult     `json:"ssh,omitempty"`
	Topology *topo.TopologyResult   `json:"topology,omitempty"`
	Error    string                 `json:"error,omitempty"`
	Evidence []Evidence             `json:"evidence,omitempty"`
}

type LatencyResult struct {
	HTTPMs float64 `json:"http_ms"`
	TCPMs  float64 `json:"tcp_ms"`
}

type SpeedResult struct {
	Mbps    float64 `json:"mbps"`
	Bytes   int64   `json:"bytes"`
	Seconds float64 `json:"seconds"`
}

// TLSCertInfo holds the leaf certificate details from an HTTPS response.
type TLSCertInfo struct {
	FingerprintSHA256 string `json:"fingerprint_sha256"`
	Issuer            string `json:"issuer,omitempty"`
	Subject           string `json:"subject,omitempty"`
	NotAfter          string `json:"not_after,omitempty"`
}

// Evidence records raw request/response data for independent verification.
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

func captureBodyBase64(resp *http.Response, limit int) string {
	if resp == nil || resp.Body == nil {
		return ""
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, int64(limit)))
	return base64.StdEncoding.EncodeToString(body)
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

func RunAll(ctx context.Context, proxies []clash.Proxy, cfg Config, concurrency int, logger *log.Logger) []NodeResult {
	results := make([]NodeResult, len(proxies))
	var wg sync.WaitGroup
	sem := make(chan struct{}, concurrency)

	for i, p := range proxies {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		go func(idx int, proxy clash.Proxy) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			logger.Printf("[%d/%d] testing %s (%s)", idx+1, len(proxies), proxy.Name, proxy.Type)
			results[idx] = testNode(ctx, idx, proxy, cfg, logger)
		}(i, p)
	}

	wg.Wait()
	return results
}

func errStr(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func evidenceFromChecker(ev checker.Evidence) Evidence {
	return Evidence{
		Test:       ev.Test,
		URL:        ev.URL,
		Method:     ev.Method,
		StatusCode: ev.StatusCode,
		Headers:    ev.Headers,
		Body:       ev.Body,
		Timing:     ev.Timing,
		RawError:   ev.RawError,
		TLSCert:    tlsCertFromChecker(ev.TLSCert),
	}
}

func tlsCertFromChecker(c *checker.TLSCertInfo) *TLSCertInfo {
	if c == nil {
		return nil
	}
	return &TLSCertInfo{
		FingerprintSHA256: c.FingerprintSHA256,
		Issuer:            c.Issuer,
		Subject:           c.Subject,
		NotAfter:          c.NotAfter,
	}
}

func evidenceSliceFromChecker(evs []checker.Evidence) []Evidence {
	result := make([]Evidence, len(evs))
	for i, ev := range evs {
		result[i] = evidenceFromChecker(ev)
	}
	return result
}

func evidenceFromTopo(ev topo.Evidence) Evidence {
	return Evidence{
		Test:       ev.Test,
		URL:        ev.URL,
		Method:     ev.Method,
		StatusCode: ev.StatusCode,
		Body:       ev.Body,
		Timing:     ev.Timing,
		RawError:   ev.RawError,
		TLSCert:    tlsCertFromTopo(ev.TLSCert),
	}
}

func tlsCertFromTopo(c *topo.TLSCertInfo) *TLSCertInfo {
	if c == nil {
		return nil
	}
	return &TLSCertInfo{
		FingerprintSHA256: c.FingerprintSHA256,
		Issuer:            c.Issuer,
		Subject:           c.Subject,
		NotAfter:          c.NotAfter,
	}
}

func evidenceSliceFromTopo(evs []topo.Evidence) []Evidence {
	result := make([]Evidence, len(evs))
	for i, ev := range evs {
		result[i] = evidenceFromTopo(ev)
	}
	return result
}

func testNode(ctx context.Context, idx int, p clash.Proxy, cfg Config, logger *log.Logger) NodeResult {
	result := NodeResult{
		Index:  idx,
		Name:   p.Name,
		Type:   p.Type,
		Server: p.Server,
		Port:   p.Port,
	}

	proxyURL, stop, err := startProxyForNode(ctx, p, cfg, logger)
	if err != nil {
		result.Error = fmt.Sprintf("start proxy: %v", err)
		return result
	}
	if stop != nil {
		defer stop()
	}

	var allEvidence []Evidence

	// Latency
	if !cfg.SkipLatency {
		latResult, ev := measureLatency(ctx, proxyURL, cfg.Timeout)
		result.Latency = &latResult
		allEvidence = append(allEvidence, ev...)
	}

	// Speed
	if !cfg.SkipSpeed {
		speedResult, ev := measureSpeed(ctx, proxyURL, cfg.Timeout, cfg.DownloadSize)
		result.Speed = &speedResult
		allEvidence = append(allEvidence, ev...)
	}

	// Streaming unlocks
	if !cfg.SkipUnlock {
		unlocks, ev := runUnlockChecks(ctx, proxyURL, cfg.Timeout)
		result.Unlocks = unlocks
		allEvidence = append(allEvidence, ev...)
	}

	// IP risk
	if !cfg.SkipIPRisk {
		ipRisk, ev := checker.CheckIPRisk(ctx, proxyURL, cfg.Timeout)
		result.IPRisk = &ipRisk
		allEvidence = append(allEvidence, evidenceSliceFromChecker(ev)...)
	}

	// DNS region
	if !cfg.SkipDNS {
		dns, ev := checker.CheckDNSRegion(ctx, proxyURL, cfg.Timeout)
		result.DNS = &dns
		allEvidence = append(allEvidence, evidenceSliceFromChecker(ev)...)
	}

	// SSH
	if !cfg.SkipSSH {
		ssh := checker.CheckSSH(ctx, proxyURL, cfg.Timeout)
		result.SSH = &ssh
	}

	// Topology
	if !cfg.SkipTopo {
		t, ev := topo.Analyze(ctx, proxyURL, cfg.Timeout, cfg.Timeout)
		result.Topology = &t
		allEvidence = append(allEvidence, evidenceSliceFromTopo(ev)...)
	}

	result.Evidence = allEvidence
	return result
}

func startProxyForNode(ctx context.Context, p clash.Proxy, cfg Config, logger *log.Logger) (string, func() error, error) {
	var binaryPath string
	var err error

	switch cfg.Kernel {
	case KernelMihomo:
		binaryPath, err = mihomo.EnsureBinary(ctx, cfg.BinDir, 60*time.Second)
		if err != nil {
			return "", nil, err
		}
		logger.Printf("using mihomo binary: %s", binaryPath)
		return mihomo.Start(ctx, binaryPath, p, "", 8*time.Second)
	default:
		binaryPath, err = xray.EnsureBinary(ctx, cfg.BinDir, 60*time.Second)
		if err != nil {
			return "", nil, err
		}
		nodeCfg, err := clashToXrayNode(p)
		if err != nil {
			return "", nil, err
		}
		logger.Printf("using xray binary: %s", binaryPath)
		return xray.Start(ctx, binaryPath, nodeCfg, "", 8*time.Second)
	}
}

func clashToXrayNode(p clash.Proxy) (xray.NodeConfig, error) {
	proto := strings.ToLower(p.Type)
	switch proto {
	case "ss":
		proto = "shadowsocks"
	case "vmess", "vless", "trojan", "shadowsocks":
	default:
		return xray.NodeConfig{}, fmt.Errorf("unsupported proxy type %q", p.Type)
	}

	network := "tcp"
	host := ""
	path := ""
	if p.WSOpts != nil {
		network = "ws"
		path = p.WSOpts.Path
		if p.WSOpts.Headers != nil {
			host = p.WSOpts.Headers["Host"]
		}
	}
	if p.Network != "" {
		network = p.Network
	}

	var realityPK, realitySID string
	if p.RealityOpts != nil {
		realityPK = p.RealityOpts.PublicKey
		realitySID = p.RealityOpts.ShortID
	}

	return xray.NodeConfig{
		Protocol:          proto,
		Address:           p.Server,
		Port:              p.Port,
		UUID:              p.UUID,
		Password:          p.Password,
		Cipher:            p.Cipher,
		Security:          p.Cipher,
		Network:           network,
		WSHost:            host,
		WSPath:            path,
		TLS:               p.TLS,
		ServerName:        p.SNI,
		Flow:              p.Flow,
		RealityPublicKey:  realityPK,
		RealityShortID:    realitySID,
		ClientFingerprint: p.ClientFingerprint,
	}, nil
}

func measureLatency(ctx context.Context, proxyURL string, timeout time.Duration) (LatencyResult, []Evidence) {
	var evidence []Evidence
	result := LatencyResult{}

	// TCP latency
	target := "1.1.1.1:443"
	started := time.Now()
	conn, err := proxy.DialTCP(ctx, proxyURL, target, timeout)
	elapsed := time.Since(started)
	if err == nil {
		conn.Close()
		result.TCPMs = float64(elapsed) / float64(time.Millisecond)
	}
	evidence = append(evidence, Evidence{
		Test:     "latency_tcp",
		URL:      target,
		Method:   "TCP",
		Timing:   map[string]float64{"total": float64(elapsed) / float64(time.Millisecond)},
		RawError: errStr(err),
	})

	// HTTP latency
	client, err := proxy.NewHTTPClient(proxyURL, timeout)
	if err != nil {
		return result, evidence
	}
	url := "https://www.gstatic.com/generate_204"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return result, evidence
	}
	req.Header.Set("Cache-Control", "no-cache")

	started = time.Now()
	resp, err := client.Do(req)
	elapsed = time.Since(started)
	if err == nil {
		result.HTTPMs = float64(elapsed) / float64(time.Millisecond)
		evidence = append(evidence, Evidence{
			Test:       "latency_http",
			URL:        url,
			Method:     "GET",
			StatusCode: resp.StatusCode,
			Timing:     map[string]float64{"total": float64(elapsed) / float64(time.Millisecond)},
			TLSCert:    captureTLSCert(resp),
		})
		resp.Body.Close()
	} else {
		evidence = append(evidence, Evidence{
			Test:     "latency_http",
			URL:      url,
			Method:   "GET",
			Timing:   map[string]float64{"total": float64(elapsed) / float64(time.Millisecond)},
			RawError: err.Error(),
		})
	}

	return result, evidence
}

func measureSpeed(ctx context.Context, proxyURL string, timeout time.Duration, downloadBytes int64) (SpeedResult, []Evidence) {
	client, err := proxy.NewHTTPClient(proxyURL, timeout*3)
	if err != nil {
		return SpeedResult{}, []Evidence{{Test: "speed", RawError: err.Error()}}
	}

	endpoints := []string{
		"https://speed.cloudflare.com/__down?bytes=10000000",
		"https://speed.hetzner.de/10MB.bin",
	}

	for _, endpoint := range endpoints {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		if err != nil {
			continue
		}
		req.Header.Set("Cache-Control", "no-cache")
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

		started := time.Now()
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			resp.Body.Close()
			continue
		}

		// Capture TTFB
		ttfb := time.Since(started)

		limitedBody := io.LimitReader(resp.Body, int64(downloadBytes))
		transferred, _ := io.Copy(io.Discard, limitedBody)
		elapsed := time.Since(started)
		resp.Body.Close()

		evidence := Evidence{
			Test:       "speed",
			URL:        endpoint,
			Method:     "GET",
			StatusCode: resp.StatusCode,
			Headers:    evidenceHeaders(resp),
			Body:       captureBodyBase64(resp, 256),
			Timing: map[string]float64{
				"total": float64(elapsed) / float64(time.Millisecond),
				"ttfb":  float64(ttfb) / float64(time.Millisecond),
			},
			TLSCert: captureTLSCert(resp),
		}
		return SpeedResult{
			Mbps:    mbpsFromBytes(transferred, elapsed),
			Bytes:   transferred,
			Seconds: elapsed.Seconds(),
		}, []Evidence{evidence}
	}

	return SpeedResult{}, []Evidence{{Test: "speed", RawError: "all endpoints failed"}}
}

func mbpsFromBytes(bytes int64, elapsed time.Duration) float64 {
	if bytes <= 0 || elapsed <= 0 {
		return 0
	}
	return float64(bytes*8) / elapsed.Seconds() / 1_000_000
}

func runUnlockChecks(ctx context.Context, proxyURL string, timeout time.Duration) ([]checker.UnlockStatus, []Evidence) {
	var unlocks []checker.UnlockStatus
	var evidence []Evidence

	services := []func() (checker.UnlockStatus, checker.Evidence){
		func() (checker.UnlockStatus, checker.Evidence) { return checker.CheckNetflix(ctx, proxyURL, timeout) },
		func() (checker.UnlockStatus, checker.Evidence) { return checker.CheckYouTube(ctx, proxyURL, timeout) },
		func() (checker.UnlockStatus, checker.Evidence) { return checker.CheckDisneyPlus(ctx, proxyURL, timeout) },
		func() (checker.UnlockStatus, checker.Evidence) { return checker.CheckBilibili(ctx, proxyURL, timeout) },
		func() (checker.UnlockStatus, checker.Evidence) { return checker.CheckOpenAI(ctx, proxyURL, timeout) },
		func() (checker.UnlockStatus, checker.Evidence) { return checker.CheckClaude(ctx, proxyURL, timeout) },
		func() (checker.UnlockStatus, checker.Evidence) { return checker.CheckSpotify(ctx, proxyURL, timeout) },
		func() (checker.UnlockStatus, checker.Evidence) { return checker.CheckTiktok(ctx, proxyURL, timeout) },
		func() (checker.UnlockStatus, checker.Evidence) { return checker.CheckWikipedia(ctx, proxyURL, timeout) },
	}

	for _, fn := range services {
		u, ev := fn()
		unlocks = append(unlocks, u)
		evidence = append(evidence, Evidence{
			Test:       ev.Test,
			URL:        ev.URL,
			Method:     ev.Method,
			StatusCode: ev.StatusCode,
			Headers:    ev.Headers,
			Body:       ev.Body,
			Timing:     ev.Timing,
			RawError:   ev.RawError,
		})
	}

	return unlocks, evidence
}

// --- Output formatters ---

func WriteTable(w io.Writer, results []NodeResult) {
	// Header
	fmt.Fprintf(w, "\n%-3s  %-30s  %-8s  %-10s  %-10s  %-8s  %-20s  %-20s  %-10s  %-10s\n",
		"#", "Name", "Type", "HTTP(ms)", "TCP(ms)", "Speed", "Unlocks", "IP Risk", "DNS Region", "SSH 22")
	fmt.Fprintf(w, "%s\n", strings.Repeat("-", 160))

	for _, r := range results {
		name := r.Name
		if len(name) > 28 {
			name = name[:26] + ".."
		}

		httpMs := "-"
		if r.Latency != nil && r.Latency.HTTPMs > 0 {
			httpMs = strconv.FormatFloat(r.Latency.HTTPMs, 'f', 0, 64)
		}
		tcpMs := "-"
		if r.Latency != nil && r.Latency.TCPMs > 0 {
			tcpMs = strconv.FormatFloat(r.Latency.TCPMs, 'f', 0, 64)
		}

		speed := "-"
		if r.Speed != nil && r.Speed.Mbps > 0 {
			speed = fmt.Sprintf("%.1f", r.Speed.Mbps)
		}

		unlocks := "-"
		if r.Unlocks != nil {
			var yes []string
			for _, u := range r.Unlocks {
				if u.Status == "yes" {
					yes = append(yes, u.Service)
				}
			}
			if len(yes) > 0 {
				unlocks = strings.Join(yes, ",")
			} else {
				unlocks = "none"
			}
		}

		ipRisk := "-"
		if r.IPRisk != nil {
			ipRisk = fmt.Sprintf("%.0f(%s)", r.IPRisk.RiskScore, r.IPRisk.RiskLevel)
		}

		dns := "-"
		if r.DNS != nil && r.DNS.Country != "" {
			dns = r.DNS.Country
		}

		ssh := "-"
		if r.SSH != nil {
			if r.SSH.Port22Open {
				ssh = "open"
			} else {
				ssh = "closed"
			}
		}

		if r.Error != "" {
			fmt.Fprintf(w, "%-3d  %-30s  %-8s  %s\n", r.Index+1, name, r.Type, r.Error)
		} else {
			fmt.Fprintf(w, "%-3d  %-30s  %-8s  %-10s  %-10s  %-8s  %-20s  %-20s  %-10s  %-10s\n",
				r.Index+1, name, r.Type, httpMs, tcpMs, speed, unlocks, ipRisk, dns, ssh)
		}
	}
	fmt.Fprintln(w)
}

func WriteJSON(w io.Writer, results []NodeResult) {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.Encode(results)
}

func WriteCSV(w io.Writer, results []NodeResult) {
	cw := csv.NewWriter(w)
	defer cw.Flush()

	cw.Write([]string{"index", "name", "type", "server", "port", "http_ms", "tcp_ms", "speed_mbps",
		"netflix", "youtube", "disney+", "bilibili", "openai", "claude", "spotify", "tiktok", "wikipedia",
		"ip_risk_score", "ip_risk_level", "dns_country", "ssh_22", "topology", "error"})

	for _, r := range results {
		httpMs := ""
		tcpMs := ""
		if r.Latency != nil {
			httpMs = strconv.FormatFloat(r.Latency.HTTPMs, 'f', 1, 64)
			tcpMs = strconv.FormatFloat(r.Latency.TCPMs, 'f', 1, 64)
		}
		speed := ""
		if r.Speed != nil {
			speed = strconv.FormatFloat(r.Speed.Mbps, 'f', 2, 64)
		}

		unlockMap := map[string]string{}
		for _, u := range r.Unlocks {
			unlockMap[strings.ToLower(u.Service)] = u.Status
		}

		ipScore := ""
		ipLevel := ""
		if r.IPRisk != nil {
			ipScore = strconv.FormatFloat(r.IPRisk.RiskScore, 'f', 0, 64)
			ipLevel = r.IPRisk.RiskLevel
		}

		dns := ""
		if r.DNS != nil {
			dns = r.DNS.Country
		}

		ssh := ""
		if r.SSH != nil {
			ssh = strconv.FormatBool(r.SSH.Port22Open)
		}

		topoStr := ""
		if r.Topology != nil {
			topoStr = topo.FormatTopo(*r.Topology)
		}

		cw.Write([]string{
			strconv.Itoa(r.Index), r.Name, r.Type, r.Server, strconv.Itoa(r.Port),
			httpMs, tcpMs, speed,
			unlockMap["netflix"], unlockMap["youtube premium"], unlockMap["disney+"],
			unlockMap["bilibili"], unlockMap["openai"], unlockMap["claude"],
			unlockMap["spotify"], unlockMap["tiktok"], unlockMap["wikipedia"],
			ipScore, ipLevel, dns, ssh, topoStr, r.Error,
		})
	}
}

