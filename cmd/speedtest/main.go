package main

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
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
	"github.com/anixops/speedtest/internal/clash"
	"github.com/anixops/speedtest/internal/prom"
	"github.com/anixops/speedtest/internal/probe"
	"github.com/anixops/speedtest/internal/sub"
	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
)

const version = "v0.1.0"

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
	)

	fs.StringVar(&configFile, "f", "", "path to Clash YAML config file")
	fs.StringVar(&subscriptionURL, "sub", "", "v2ray subscription URL (alternative to -f)")
	fs.StringVar(&subUserAgent, "sub-ua", "clash.meta", "User-Agent for subscription fetch")
	fs.StringVar(&outputFormat, "format", "table", "output format: table, json, csv, chart, png")
	fs.StringVar(&outputFile, "o", "", "write output to file (default: outputDir)")
	fs.StringVar(&outputDir, "output-dir", "output", "directory for output files (default: output/)")
	fs.StringVar(&binDir, "bin-dir", "bin", "directory for downloaded kernel binaries (default: bin/)")
	fs.StringVar(&keyDir, "key-dir", ".keys", "directory for Ed25519 signing keys (default: .keys/)")
	fs.StringVar(&kernel, "kernel", "mihomo", "proxy kernel: mihomo or xray")
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

	if err := fs.Parse(args); err != nil {
		return 2
	}

	if showVersion {
		fmt.Fprintln(stdout, version)
		return 0
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
		nodes, err := sub.FetchAndParse(ctx, subscriptionURL, subUserAgent)
		if err != nil {
			fmt.Fprintf(stderr, "failed to fetch subscription: %v\n", err)
			return 1
		}
		for _, n := range nodes {
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

	logger := log.New(stderr, "", log.LstdFlags)
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

	kernelMode := probe.Kernel(strings.ToLower(strings.TrimSpace(kernel)))
	if kernelMode != probe.KernelXray && kernelMode != probe.KernelMihomo {
		fmt.Fprintf(stderr, "error: unsupported kernel %q (allowed: xray, mihomo)\n", kernel)
		return 2
	}

	if latencyOnly {
		skipSpeed = true
		skipUnlock = true
		skipTopo = true
		skipIPRisk = true
		skipDNS = true
		skipSSH = true
	}

	cfg := probe.Config{
		Kernel:        kernelMode,
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
	}

	results := probe.RunAll(ctx, proxies, cfg, concurrency, logger)

	// Push to Prometheus Pushgateway
	if pushgateway != "" {
		cfAccessID := os.Getenv("CF_ACCESS_CLIENT_ID")
		cfAccessSecret := os.Getenv("CF_ACCESS_CLIENT_SECRET")
		if err := prom.PushMetrics(pushgateway, promJob, results, cfAccessID, cfAccessSecret); err != nil {
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

	var w io.Writer = stdout
	if outputFile == "" {
		// Default output file in output directory based on format
		var baseName string
		switch strings.ToLower(outputFormat) {
		case "json":
			baseName = "report.json"
		case "csv":
			baseName = "report.csv"
		case "chart":
			baseName = "report.html"
		default:
			baseName = "report.txt"
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
	}

	if p.Type == "ss" {
		p.Type = "shadowsocks"
	}

	return p
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
			if key != "" {
				os.Setenv(key, val)
			}
		}
	}
}
