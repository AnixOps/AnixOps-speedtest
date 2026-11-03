package main

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/anixops/speedtest/internal/ats"
	"github.com/anixops/speedtest/internal/chart"
	"github.com/anixops/speedtest/internal/checker"
	"github.com/anixops/speedtest/internal/clash"
	"github.com/anixops/speedtest/internal/probe"
	"github.com/anixops/speedtest/internal/prom"
	"github.com/anixops/speedtest/internal/sub"
	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
)

// Set at build time via -ldflags "-X main.version=... -X main.commit=... -X main.date=...".
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	loadEnvFile()
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) > 0 && args[0] == "verify" {
		return runVerify(args[1:], stdout, stderr)
	}

	fs := flag.NewFlagSet("speedtest", flag.ContinueOnError)
	fs.SetOutput(stderr)

	var (
		configFile      string
		subscriptionURL string
		subUserAgent    string
		subCache        string
		outputFormat    string
		outputFile      string
		outputDir       string
		binDir          string
		keyDir          string
		kernel          string
		timeout         time.Duration
		concurrency     int
		skipLatency     bool
		skipSpeed       bool
		skipUnlock      bool
		skipTopo        bool
		skipIPRisk      bool
		skipDNS         bool
		skipSSH         bool
		showVersion     bool
		proxyFilter     string
		downloadSize    int64
		disableATS      bool
		noSign          bool
		latencyOnly     bool
		pushgateway     string
		promJob         string
		repeat          int
		redact          bool
		speedTimeout    time.Duration
		unlockTimeout   time.Duration
		jsonlPath       string
		quiet           bool
		configPath      string
		unlockRules     string
		mihomoBatch     int
		anxBin          string
		throughput      bool
		tpConns         int
		tpDuration      time.Duration
		tpNoUpload      bool
		tpMaxBytes      int64
		tpDownURL       string
		tpUpURL         string
	)

	fs.StringVar(&configFile, "f", "", "path to Clash YAML config file")
	fs.StringVar(&subscriptionURL, "sub", "", "v2ray subscription URL (alternative to -f)")
	fs.StringVar(&subUserAgent, "sub-ua", "clash.meta", "User-Agent for subscription fetch")
	fs.StringVar(&subCache, "sub-cache", "", "file holding the last good -sub body; used when a fetch fails")
	fs.StringVar(&outputFormat, "format", "table", "output format: table, json, csv, chart, png")
	fs.StringVar(&outputFile, "o", "", "write output to file (default: outputDir)")
	fs.StringVar(&outputDir, "output-dir", "output", "directory for output files (default: output/)")
	fs.StringVar(&binDir, "bin-dir", "bin", "directory for downloaded kernel binaries (default: bin/)")
	fs.StringVar(&keyDir, "key-dir", ".keys", "directory for Ed25519 signing keys (default: .keys/)")
	fs.StringVar(&kernel, "kernel", "mihomo", "proxy kernel: mihomo, xray or anx")
	fs.StringVar(&anxBin, "anx-bin", "", "anx-proxy binary for -kernel anx (default: $SPEEDTEST_ANX_BIN, <bin-dir>/anx-proxy, PATH)")
	fs.DurationVar(&timeout, "timeout", 10*time.Second, "per-probe timeout")
	fs.IntVar(&concurrency, "c", 5, "concurrent test workers")
	fs.BoolVar(&skipLatency, "skip-latency", false, "skip HTTP latency test")
	fs.BoolVar(&skipSpeed, "skip-speed", false, "skip download speed test")
	fs.BoolVar(&skipUnlock, "skip-unlock", false, "skip streaming unlock tests")
	fs.BoolVar(&skipTopo, "skip-topo", false, "skip topology analysis")
	fs.BoolVar(&skipIPRisk, "skip-iprisk", false, "skip IP risk check")
	fs.BoolVar(&skipDNS, "skip-dns", false, "skip DNS region detection")
	fs.BoolVar(&skipSSH, "skip-ssh", false, "skip SSH port 22 check")
	fs.BoolVar(&showVersion, "version", false, "print version and exit")
	fs.StringVar(&proxyFilter, "filter", "", "only test proxies whose name contains this substring")
	fs.Int64Var(&downloadSize, "download-size", 10*1024*1024, "bytes to download for speed test")
	fs.BoolVar(&disableATS, "no-ats", false, "disable blockchain anchoring (OpenTimestamps)")
	fs.BoolVar(&noSign, "no-sign", false, "disable Ed25519 digital signature")
	fs.BoolVar(&latencyOnly, "latency-only", false, "only test HTTP/TCP latency, skip all other checks")
	fs.StringVar(&pushgateway, "pushgateway", "", "Prometheus Pushgateway URL (e.g. http://host:9091)")
	fs.StringVar(&promJob, "prom-job", "speedtest", "Prometheus job name for Pushgateway")

	fs.IntVar(&repeat, "repeat", 1, "latency samples per node; >1 reports median, jitter and loss")
	fs.BoolVar(&redact, "redact", false, "mask server/exit/entry IPs and drop raw evidence so the report is safe to share")

	fs.DurationVar(&speedTimeout, "speed-timeout", 0, "download-test timeout (default: 3x -timeout)")
	fs.DurationVar(&unlockTimeout, "unlock-timeout", 0, "per-service unlock-check timeout (default: -timeout)")
	fs.StringVar(&jsonlPath, "jsonl", "", "stream each node's result as a JSON line to this file as it completes (- for stdout)")
	fs.BoolVar(&quiet, "q", false, "suppress progress logging")

	fs.IntVar(&mihomoBatch, "mihomo-batch", 0, "host up to N nodes per mihomo process (0 = one process per node)")
	fs.StringVar(&unlockRules, "unlock-rules", "", "YAML file that overrides/extends the built-in unlock rules")
	fs.StringVar(&configPath, "config", "", "YAML file of option defaults, keyed by flag name (default: ./speedtest.yaml if present)")

	fs.BoolVar(&throughput, "throughput", false, "run the multi-connection download/upload suite with loaded latency")
	fs.IntVar(&tpConns, "tp-conns", 8, "parallel connections per direction for -throughput")
	fs.DurationVar(&tpDuration, "tp-duration", 8*time.Second, "how long each -throughput direction runs")
	fs.BoolVar(&tpNoUpload, "tp-no-upload", false, "-throughput: download only")
	fs.Int64Var(&tpMaxBytes, "tp-max-bytes", 0, "-throughput: stop a direction after this many bytes (0 = no cap)")
	fs.StringVar(&tpDownURL, "tp-down-url", "", "-throughput download URL; a trailing '=' gets the chunk size (default Cloudflare __down)")
	fs.StringVar(&tpUpURL, "tp-up-url", "", "-throughput upload URL accepting POST (default Cloudflare __up)")

	if err := fs.Parse(args); err != nil {
		return 2
	}
	if err := applyConfigFile(fs, configPath); err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 2
	}

	if showVersion {
		fmt.Fprintf(stdout, "%s (commit %s, built %s)\n", version, commit, date)
		return 0
	}

	switch strings.ToLower(outputFormat) {
	case "table", "json", "csv", "chart", "png":
	default:
		fmt.Fprintf(stderr, "error: unsupported format %q (allowed: table, json, csv, chart, png)\n", outputFormat)
		return 2
	}

	hasConfig := strings.TrimSpace(configFile) != ""
	hasSub := strings.TrimSpace(subscriptionURL) != ""

	if !hasConfig && !hasSub {
		fmt.Fprintln(stderr, "error: either -f (config file) or -sub (subscription URL) is required")
		fmt.Fprintln(stderr, "Usage: speedtest -f config.yaml [options]")
		fmt.Fprintln(stderr, "       speedtest -sub <subscription-url> [options]")
		fs.Usage()
		return 2
	}
	if hasConfig && hasSub {
		fmt.Fprintln(stderr, "error: cannot use both -f and -sub at the same time")
		return 2
	}

	kernelMode := probe.Kernel(strings.ToLower(strings.TrimSpace(kernel)))
	switch kernelMode {
	case probe.KernelXray, probe.KernelMihomo, probe.KernelAnx:
	default:
		fmt.Fprintf(stderr, "error: unsupported kernel %q (allowed: xray, mihomo, anx)\n", kernel)
		return 2
	}
	// The anx kernel needs share links (anx:// among them), which AnixOps
	// Control serves to the AnixOps Net User-Agent; its default UA gets Clash YAML.
	if kernelMode == probe.KernelAnx && !flagSet(fs, "sub-ua") {
		subUserAgent = anxSubUserAgent
	}

	var proxies []clash.Proxy
	var source string

	if hasConfig {
		var err error
		proxies, err = clash.ParseFile(configFile)
		if err != nil {
			fmt.Fprintf(stderr, "failed to parse Clash config: %v\n", err)
			return 1
		}
		source = configFile
	} else {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		res, err := sub.FetchWithCache(ctx, subscriptionURL, subUserAgent, subCache)
		if err != nil && len(res.Nodes) == 0 {
			fmt.Fprintf(stderr, "failed to fetch subscription: %v\n", err)
			return 1
		}
		if err != nil {
			fmt.Fprintf(stderr, "warning: %v\n", err)
		}
		if res.FromCache {
			fmt.Fprintf(stderr, "warning: failed to fetch subscription (%v); using the cached copy %s\n", res.FetchErr, subCache)
		}
		for _, n := range res.Nodes {
			p := subNodeToClashProxy(n)
			if p.Name != "" && p.Server != "" && p.Port > 0 {
				proxies = append(proxies, p)
			}
		}
		source = subscriptionURL
	}

	if proxyFilter != "" {
		var filtered []clash.Proxy
		for _, p := range proxies {
			if strings.Contains(strings.ToLower(p.Name), strings.ToLower(proxyFilter)) {
				filtered = append(filtered, p)
			}
		}
		proxies = filtered
	}

	if len(proxies) == 0 {
		fmt.Fprintln(stderr, "no proxies found in config")
		return 1
	}

	logOut := stderr
	if quiet {
		logOut = io.Discard
	}
	logger := log.New(logOut, "", log.LstdFlags)
	logger.Printf("loaded %d proxies from %s", len(proxies), source)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Ensure output and bin directories exist
	for _, dir := range []string{outputDir, binDir} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			fmt.Fprintf(stderr, "failed to create directory %s: %v\n", dir, err)
			return 1
		}
	}

	if latencyOnly {
		skipSpeed = true
		skipUnlock = true
		skipTopo = true
		skipIPRisk = true
		skipDNS = true
		skipSSH = true
	}

	rules, err := checker.LoadRules(unlockRules)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 2
	}

	cfg := probe.Config{
		UnlockRules:   rules,
		MihomoBatch:   mihomoBatch,
		Kernel:        kernelMode,
		AnxBin:        anxBin,
		Timeout:       timeout,
		DownloadSize:  downloadSize,
		SkipLatency:   skipLatency,
		SkipSpeed:     skipSpeed,
		SkipUnlock:    skipUnlock,
		SkipTopo:      skipTopo,
		SkipIPRisk:    skipIPRisk,
		SkipDNS:       skipDNS,
		SkipSSH:       skipSSH,
		BinDir:        binDir,
		Repeat:        repeat,
		SpeedTimeout:  speedTimeout,
		UnlockTimeout: unlockTimeout,
	}
	if throughput {
		cfg.Throughput = &probe.ThroughputConfig{
			Conns:    tpConns,
			Duration: tpDuration,
			Upload:   !tpNoUpload,
			MaxBytes: tpMaxBytes,
			DownURL:  tpDownURL,
			UpURL:    tpUpURL,
		}
	}
	if jsonlPath != "" {
		jw := stdout
		if jsonlPath != "-" {
			f, err := os.Create(jsonlPath)
			if err != nil {
				fmt.Fprintf(stderr, "failed to create jsonl file: %v\n", err)
				return 1
			}
			defer f.Close()
			jw = f
		}
		enc := json.NewEncoder(jw)
		enc.SetEscapeHTML(false)
		cfg.OnResult = func(r probe.NodeResult) {
			if redact {
				r = probe.Redact([]probe.NodeResult{r})[0]
			}
			_ = enc.Encode(r)
		}
	}

	results := probe.RunAll(ctx, proxies, cfg, concurrency, logger)
	if redact {
		results = probe.Redact(results)
	}

	// Push to Prometheus Pushgateway
	if pushgateway != "" {
		cfAccessID := os.Getenv("CF_ACCESS_CLIENT_ID")
		cfAccessSecret := os.Getenv("CF_ACCESS_CLIENT_SECRET")
		if err := prom.PushMetrics(pushgateway, promJob, string(kernelMode), results, cfAccessID, cfAccessSecret); err != nil {
			logger.Printf("warning: failed to push metrics: %v", err)
		} else {
			logger.Printf("pushed metrics to Pushgateway %s (job=%s)", pushgateway, promJob)
		}
		// When pushing, skip file output and return
		return 0
	}

	// Generate anti-tamper certificate
	enableOTS := !disableATS
	var privKey ed25519.PrivateKey
	var mlDSAPriv *mldsa87.PrivateKey
	var pubKeyFingerprint string
	if !noSign {
		pub, priv, err := ats.LoadOrGenerateKeyPair(keyDir)
		if err != nil {
			logger.Printf("warning: failed to load Ed25519 signing key: %v", err)
		} else {
			privKey = priv
			pubKeyFingerprint = ats.KeyFingerprint(pub)
			logger.Printf("Ed25519 signing key loaded (pub: %s...)", hexPubKey(pub))
			logger.Printf("Trust Anchor (key fingerprint): %s", pubKeyFingerprint)
		}
		mlDSAPub, mlDSAPrivKey, err := ats.LoadOrGenerateMLDSAKeyPair(keyDir)
		if err != nil {
			logger.Printf("warning: failed to load ML-DSA signing key: %v", err)
		} else {
			mlDSAPriv = mlDSAPrivKey
			logger.Printf("ML-DSA-87 signing key loaded (hash: %s)", ats.MLDSAHash(mlDSAPub))
		}
	}
	cert, err := ats.GenerateCertificate(results, version, enableOTS, privKey, mlDSAPriv)
	if err != nil {
		logger.Printf("warning: failed to generate certificate: %v", err)
	} else {
		if cert.OTSStatus == "pending" {
			logger.Printf("blockchain anchoring is pending, proof will be available later")
		}
		if cert.PublicKeyOTS != "" && cert.PublicKeyOTSS != "confirmed" {
			logger.Printf("key anchoring to blockchain is pending")
		} else if cert.PublicKeyOTS != "" {
			logger.Printf("public key anchored to blockchain (OpenTimestamps)")
		}
	}

	// Handle PNG format
	if strings.ToLower(outputFormat) == "png" {
		pngPath := outputFile
		if pngPath == "" {
			pngPath = filepath.Join(outputDir, "speedtest.png")
		}
		if err := chart.GeneratePNG(pngPath, results, cert); err != nil {
			fmt.Fprintf(stderr, "failed to generate PNG: %v\n", err)
			return 1
		}
		fmt.Fprintf(stdout, "Report saved to %s\n", pngPath)
		return 0
	}

	w := stdout
	if outputFile == "" && strings.ToLower(outputFormat) != "table" {
		// Default output file in output directory based on format
		var baseName string
		switch strings.ToLower(outputFormat) {
		case "json":
			baseName = "report.json"
		case "csv":
			baseName = "report.csv"
		case "chart":
			baseName = "report.html"
		}
		outputFile = filepath.Join(outputDir, baseName)
	}
	if outputFile != "" {
		f, err := os.Create(outputFile)
		if err != nil {
			fmt.Fprintf(stderr, "failed to create output file: %v\n", err)
			return 1
		}
		defer f.Close()
		w = f
	}

	switch strings.ToLower(outputFormat) {
	case "json":
		envelope := ats.ReportEnvelope{
			Results:     results,
			Certificate: cert,
		}
		ats.WriteJSON(w, envelope)
	case "csv":
		probe.WriteCSV(w, results)
	case "chart":
		chart.Render(w, results, cert)
	default:
		probe.WriteTable(w, results)
	}

	return 0
}

func subNodeToClashProxy(n sub.Node) clash.Proxy {
	port, _ := strconv.Atoi(n.Port)

	var wsOpts *clash.WSOptions
	if n.Network == "ws" || n.Host != "" || n.Path != "" {
		wsOpts = &clash.WSOptions{
			Path: n.Path,
		}
		if n.Host != "" {
			wsOpts.Headers = map[string]string{"Host": n.Host}
		}
	}

	var realityOpts *clash.RealityOptions
	if n.RealityPublicKey != "" {
		realityOpts = &clash.RealityOptions{
			PublicKey: n.RealityPublicKey,
			ShortID:   n.RealityShortID,
		}
	}

	network := n.Network
	if network == "" {
		network = "tcp"
	}

	tls := n.TLS == "true" || n.TLS == "1" || n.TLS == "tls"

	p := clash.Proxy{
		Name:              n.Name,
		Type:              n.Protocol,
		Server:            n.Server,
		Port:              port,
		UUID:              n.UUID,
		Password:          n.Password,
		Cipher:            n.Method,
		Network:           network,
		TLS:               tls,
		SNI:               n.SNI,
		SkipCertVerify:    true,
		WSOpts:            wsOpts,
		RealityOpts:       realityOpts,
		ClientFingerprint: n.ClientFingerprint,
		Flow:              n.Flow,
		Extra:             n.Extra,
		ShareLink:         n.Link,
	}

	if p.Type == "ss" {
		p.Type = "shadowsocks"
	}

	return p
}

// anxSubUserAgent makes AnixOps Control answer with its AnixOps Net share-link
// format, the only one that carries anx:// nodes.
const anxSubUserAgent = "AnixOpsNet"

// flagSet reports whether name was given on the command line or by the config file.
func flagSet(fs *flag.FlagSet, name string) bool {
	set := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == name {
			set = true
		}
	})
	return set
}

func hexPubKey(pub ed25519.PublicKey) string {
	return hex.EncodeToString(pub[:8])
}

// loadEnvFile reads .env in the executable directory and sets environment variables.
func loadEnvFile() {
	exe, err := os.Executable()
	if err != nil {
		return
	}
	dir := filepath.Dir(exe)
	data, err := os.ReadFile(filepath.Join(dir, ".env"))
	if err != nil {
		return
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			key := strings.TrimSpace(parts[0])
			val := strings.TrimSpace(parts[1])
			// Strip surrounding quotes if present
			if len(val) >= 2 && val[0] == '"' && val[len(val)-1] == '"' {
				val = val[1 : len(val)-1]
			}
			// Real environment wins over the .env file.
			if _, set := os.LookupEnv(key); key != "" && !set {
				_ = os.Setenv(key, val)
			}
		}
	}
}
