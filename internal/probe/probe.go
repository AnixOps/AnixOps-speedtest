package probe

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
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
	Kernel       Kernel
	Timeout      time.Duration
	DownloadSize int64
	SkipLatency  bool
	SkipSpeed    bool
	SkipUnlock   bool
	SkipTopo     bool
	SkipIPRisk   bool
	SkipDNS      bool
	SkipSSH      bool
	BinDir       string
	// Repeat is how many latency samples to take per node (<=1 means one).
	Repeat int
	// SpeedTimeout / UnlockTimeout override Timeout for those phases (0 = default:
	// 3x Timeout for the download, Timeout for unlock checks).
	SpeedTimeout  time.Duration
	UnlockTimeout time.Duration
	// UnlockRules overrides the built-in unlock rules when non-nil.
	UnlockRules []checker.Rule
	// MihomoBatch > 1 hosts up to that many nodes per mihomo process (one SOCKS
	// listener each) instead of one process per node. Mihomo kernel only.
	MihomoBatch int
	// OnResult, when set, receives each node's result as soon as it finishes.
	// Calls are serialized.
	OnResult func(NodeResult)
}

type NodeResult struct {
	Index    int                      `json:"index"`
	Name     string                   `json:"name"`
	Type     string                   `json:"type"`
	Server   string                   `json:"server"`
	Port     int                      `json:"port"`
	Latency  *LatencyResult           `json:"latency,omitempty"`
	Speed    *SpeedResult             `json:"speed,omitempty"`
	Unlocks  []checker.UnlockStatus   `json:"unlocks,omitempty"`
	IPRisk   *checker.IPRiskResult    `json:"ip_risk,omitempty"`
	DNS      *checker.DNSRegionResult `json:"dns,omitempty"`
	SSH      *checker.SSHResult       `json:"ssh,omitempty"`
	Topology *topo.TopologyResult     `json:"topology,omitempty"`
	Error    string                   `json:"error,omitempty"`
	Evidence []Evidence               `json:"evidence,omitempty"`
}

type LatencyResult struct {
	HTTPMs float64 `json:"http_ms"`
	TCPMs  float64 `json:"tcp_ms"`
	// Populated when more than one sample was taken; HTTPMs/TCPMs then hold medians.
	Samples      int     `json:"samples,omitempty"`
	HTTPJitterMs float64 `json:"http_jitter_ms,omitempty"`
	HTTPLossPct  float64 `json:"http_loss_pct,omitempty"`
	TCPLossPct   float64 `json:"tcp_loss_pct,omitempty"`
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
	if concurrency < 1 {
		concurrency = 1
	}
	if cfg.Kernel == KernelMihomo && cfg.MihomoBatch > 1 {
		return runBatched(ctx, proxies, cfg, concurrency, logger)
	}
	return runPool(ctx, proxies, cfg, concurrency, logger, func(idx int, p clash.Proxy) NodeResult {
		return testNode(ctx, idx, p, cfg, logger)
	})
}

// runBatched tests proxies in groups of cfg.MihomoBatch, one mihomo process per
// group. A group that fails to start (e.g. mihomo rejects one proxy's options)
// degrades to one process per node so a single bad node can't sink its neighbours.
func runBatched(ctx context.Context, proxies []clash.Proxy, cfg Config, concurrency int, logger *log.Logger) []NodeResult {
	results := make([]NodeResult, len(proxies))
	binary, err := mihomo.EnsureBinary(ctx, cfg.BinDir, 60*time.Second)
	if err != nil {
		for i, p := range proxies {
			results[i] = newResult(i, p)
			results[i].Error = fmt.Sprintf("start proxy: %v", err)
		}
		return results
	}
	binaryOnce.Do(func() { logger.Printf("using mihomo binary: %s (batches of %d)", binary, cfg.MihomoBatch) })

	var mu sync.Mutex
	done := 0
	report := func(r NodeResult) {
		mu.Lock()
		defer mu.Unlock()
		done++
		logger.Printf("[%d/%d] %s", done, len(proxies), summarize(r))
		if cfg.OnResult != nil {
			cfg.OnResult(r)
		}
	}

	for start := 0; start < len(proxies) && ctx.Err() == nil; start += cfg.MihomoBatch {
		end := min(start+cfg.MihomoBatch, len(proxies))
		group := proxies[start:end]
		urls, stop, err := mihomo.StartBatch(ctx, binary, group, "", 15*time.Second)

		var urlOf func(i int) (string, bool)
		if err != nil {
			logger.Printf("batch %d-%d failed to start (%v); testing those nodes one by one", start+1, end, err)
			urlOf = func(int) (string, bool) { return "", false }
		} else {
			urlOf = func(i int) (string, bool) { return urls[i], true }
		}

		sub := runPoolOffset(ctx, group, start, concurrency, func(idx int, p clash.Proxy) NodeResult {
			if u, ok := urlOf(idx - start); ok {
				return testNodeVia(ctx, idx, p, cfg, u)
			}
			return testNode(ctx, idx, p, cfg, logger)
		}, report)
		copy(results[start:end], sub)
		if stop != nil {
			_ = stop()
		}
	}
	return results
}

func runPool(ctx context.Context, proxies []clash.Proxy, cfg Config, concurrency int, logger *log.Logger, run func(int, clash.Proxy) NodeResult) []NodeResult {
	var mu sync.Mutex
	done := 0
	report := func(r NodeResult) {
		mu.Lock()
		defer mu.Unlock()
		done++
		logger.Printf("[%d/%d] %s", done, len(proxies), summarize(r))
		if cfg.OnResult != nil {
			cfg.OnResult(r)
		}
	}
	return runPoolOffset(ctx, proxies, 0, concurrency, run, report)
}

// runPoolOffset runs run for each proxy with bounded concurrency; indexes passed
// to run are offset+position so results keep their global node number.
func runPoolOffset(ctx context.Context, proxies []clash.Proxy, offset, concurrency int, run func(int, clash.Proxy) NodeResult, report func(NodeResult)) []NodeResult {
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
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				results[idx-offset] = NodeResult{Index: idx, Name: proxy.Name, Type: proxy.Type, Server: proxy.Server, Port: proxy.Port, Error: "cancelled"}
				return
			}
			defer func() { <-sem }()

			r := run(idx, proxy)
			results[idx-offset] = r

			report(r)
		}(offset+i, p)
	}

	wg.Wait()
	return results
}

// summarize renders a one-line outcome for progress logging.
func summarize(r NodeResult) string {
	if r.Error != "" {
		return fmt.Sprintf("✗ %s (%s): %s", r.Name, r.Type, r.Error)
	}
	parts := []string{fmt.Sprintf("✓ %s (%s)", r.Name, r.Type)}
	if r.Latency != nil && r.Latency.HTTPMs > 0 {
		parts = append(parts, fmt.Sprintf("http=%.0fms", r.Latency.HTTPMs))
	}
	if r.Speed != nil && r.Speed.Mbps > 0 {
		parts = append(parts, fmt.Sprintf("speed=%.1fMbps", r.Speed.Mbps))
	}
	return strings.Join(parts, " ")
}

// Up reports whether the node answered: no error, and, if latency was measured,
// at least one probe succeeded.
func (r NodeResult) Up() bool {
	if r.Error != "" {
		return false
	}
	return r.Latency == nil || r.Latency.HTTPMs > 0 || r.Latency.TCPMs > 0
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
	proxyURL, stop, err := startProxyForNode(ctx, p, cfg, logger)
	if err != nil {
		r := newResult(idx, p)
		r.Error = fmt.Sprintf("start proxy: %v", err)
		return r
	}
	if stop != nil {
		defer func() { _ = stop() }()
	}
	return testNodeVia(ctx, idx, p, cfg, proxyURL)
}

func newResult(idx int, p clash.Proxy) NodeResult {
	return NodeResult{Index: idx, Name: p.Name, Type: p.Type, Server: p.Server, Port: p.Port}
}

// testNodeVia runs every enabled check through an already-running proxy.
func testNodeVia(ctx context.Context, idx int, p clash.Proxy, cfg Config, proxyURL string) NodeResult {
	result := newResult(idx, p)

	var allEvidence []Evidence

	// Latency
	if !cfg.SkipLatency {
		latResult, ev := measureLatencyRepeated(ctx, proxyURL, cfg.Timeout, cfg.Repeat)
		result.Latency = &latResult
		allEvidence = append(allEvidence, ev...)

		// A node that answers neither probe is dead; running the remaining checks
		// would only burn a timeout per check.
		if latResult.HTTPMs <= 0 && latResult.TCPMs <= 0 {
			result.Error = "node unreachable: all latency probes failed"
			result.Evidence = allEvidence
			return result
		}
	}

	// Speed
	if !cfg.SkipSpeed {
		speedTimeout := cfg.SpeedTimeout
		if speedTimeout <= 0 {
			speedTimeout = cfg.Timeout * 3
		}
		speedResult, ev := measureSpeed(ctx, proxyURL, speedTimeout, cfg.DownloadSize)
		result.Speed = &speedResult
		allEvidence = append(allEvidence, ev...)
	}

	// Streaming unlocks
	if !cfg.SkipUnlock {
		unlockTimeout := cfg.UnlockTimeout
		if unlockTimeout <= 0 {
			unlockTimeout = cfg.Timeout
		}
		unlocks, ev := runUnlockChecks(ctx, proxyURL, unlockTimeout, cfg.UnlockRules)
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

var binaryOnce sync.Once

func startProxyForNode(ctx context.Context, p clash.Proxy, cfg Config, logger *log.Logger) (string, func() error, error) {
	var binaryPath string
	var err error

	switch cfg.Kernel {
	case KernelMihomo:
		binaryPath, err = mihomo.EnsureBinary(ctx, cfg.BinDir, 60*time.Second)
		if err != nil {
			return "", nil, err
		}
		binaryOnce.Do(func() { logger.Printf("using mihomo binary: %s", binaryPath) })
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
		binaryOnce.Do(func() { logger.Printf("using xray binary: %s", binaryPath) })
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

	// TCP latency. A SOCKS5 CONNECT is acknowledged by the local kernel before the
	// upstream connection exists, so a bare dial "succeeds" even for dead nodes.
	// Completing a TLS handshake with the target forces a real round trip through
	// the node, so TCPMs means connect + one handshake RTT.
	target := "1.1.1.1:443"
	started := time.Now()
	tcpErr := tlsRoundTrip(ctx, proxyURL, target, "one.one.one.one", timeout)
	elapsed := time.Since(started)
	if tcpErr == nil {
		result.TCPMs = float64(elapsed) / float64(time.Millisecond)
	}
	evidence = append(evidence, Evidence{
		Test:     "latency_tcp",
		URL:      target,
		Method:   "TCP+TLS",
		Timing:   map[string]float64{"total": float64(elapsed) / float64(time.Millisecond)},
		RawError: errStr(tcpErr),
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

// tlsRoundTrip dials target through the proxy and completes a TLS handshake.
func tlsRoundTrip(ctx context.Context, proxyURL, target, serverName string, timeout time.Duration) error {
	conn, err := proxy.DialTCP(ctx, proxyURL, target, timeout)
	if err != nil {
		return err
	}
	defer conn.Close()
	hctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return tls.Client(conn, &tls.Config{ServerName: serverName, MinVersion: tls.VersionTLS12}).HandshakeContext(hctx)
}

func measureSpeed(ctx context.Context, proxyURL string, timeout time.Duration, downloadBytes int64) (SpeedResult, []Evidence) {
	client, err := proxy.NewHTTPClient(proxyURL, timeout)
	if err != nil {
		return SpeedResult{}, []Evidence{{Test: "speed", RawError: err.Error()}}
	}

	if downloadBytes <= 0 {
		downloadBytes = 10 << 20
	}
	endpoints := []string{
		fmt.Sprintf("https://speed.cloudflare.com/__down?bytes=%d", downloadBytes),
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

func runUnlockChecks(ctx context.Context, proxyURL string, timeout time.Duration, rules []checker.Rule) ([]checker.UnlockStatus, []Evidence) {
	if rules == nil {
		rules = checker.DefaultRules()
	}
	unlocks, evs := checker.RunUnlockChecks(ctx, proxyURL, timeout, rules)
	evidence := make([]Evidence, len(evs))
	for i, ev := range evs {
		evidence[i] = evidenceFromChecker(ev)
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
			if r.Latency.Samples > 1 {
				httpMs += fmt.Sprintf("±%.0f", r.Latency.HTTPJitterMs)
				if r.Latency.HTTPLossPct > 0 {
					httpMs += fmt.Sprintf(" L%.0f%%", r.Latency.HTTPLossPct)
				}
			}
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

	_ = cw.Write([]string{"index", "name", "type", "server", "port", "http_ms", "tcp_ms", "speed_mbps",
		"netflix", "youtube", "disney+", "bilibili", "openai", "claude", "spotify", "tiktok", "wikipedia",
		"ip_risk_score", "ip_risk_level", "dns_country", "ssh_22", "topology", "error",
		"http_jitter_ms", "http_loss_pct"})

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

		jit, loss := "", ""
		if r.Latency != nil && r.Latency.Samples > 1 {
			jit = strconv.FormatFloat(r.Latency.HTTPJitterMs, 'f', 1, 64)
			loss = strconv.FormatFloat(r.Latency.HTTPLossPct, 'f', 1, 64)
		}

		_ = cw.Write([]string{
			strconv.Itoa(r.Index), r.Name, r.Type, r.Server, strconv.Itoa(r.Port),
			httpMs, tcpMs, speed,
			unlockMap["netflix"], unlockMap["youtube premium"], unlockMap["disney+"],
			unlockMap["bilibili"], unlockMap["openai"], unlockMap["claude"],
			unlockMap["spotify"], unlockMap["tiktok"], unlockMap["wikipedia"],
			ipScore, ipLevel, dns, ssh, topoStr, r.Error, jit, loss,
		})
	}
}
