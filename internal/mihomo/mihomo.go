package mihomo

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/anixops/speedtest/internal/clash"
	"github.com/anixops/speedtest/internal/kernel"
	"gopkg.in/yaml.v3"
)

var downloadMu sync.Mutex

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

type NodeConfig struct {
	clash.Proxy
}

// Start launches mihomo with a single-node config, waits for the socks5 listener, and returns the proxy URL plus a stop hook.
func Start(ctx context.Context, binaryPath string, proxy clash.Proxy, workDir string, startupTimeout time.Duration) (string, func() error, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	binaryPath = strings.TrimSpace(binaryPath)
	if binaryPath == "" {
		return "", nil, fmt.Errorf("mihomo binary path is required")
	}
	if startupTimeout <= 0 {
		return "", nil, fmt.Errorf("startup timeout must be > 0, got %s", startupTimeout)
	}

	var ports [3]int
	for i := range ports {
		addr, err := kernel.ReservePort()
		if err != nil {
			return "", nil, err
		}
		if ports[i], err = portOf(addr); err != nil {
			return "", nil, err
		}
	}
	socksPort, httpPort, mixedPort := ports[0], ports[1], ports[2]

	if workDir != "" {
		if err := os.MkdirAll(workDir, 0o755); err != nil {
			return "", nil, fmt.Errorf("failed to prepare workDir: %w", err)
		}
	}
	tmpDir, err := os.MkdirTemp(workDir, "speedtest-mihomo-config-")
	if err != nil {
		return "", nil, fmt.Errorf("failed to create temp dir: %w", err)
	}

	configYAML, err := buildConfig(proxy, socksPort, httpPort, mixedPort)
	if err != nil {
		os.RemoveAll(tmpDir)
		return "", nil, err
	}

	configPath := filepath.Join(tmpDir, "config.yaml")
	if err := os.WriteFile(configPath, configYAML, 0o600); err != nil {
		os.RemoveAll(tmpDir)
		return "", nil, fmt.Errorf("failed to write config: %w", err)
	}

	execPath := kernel.ExecPath(binaryPath)
	cmd := exec.CommandContext(ctx, execPath, "-d", tmpDir, "-f", configPath)
	cmd.Stdout = nil
	stderrTail := &kernel.TailBuffer{Max: 2048}
	cmd.Stderr = stderrTail
	if err := cmd.Start(); err != nil {
		os.RemoveAll(tmpDir)
		return "", nil, fmt.Errorf("failed to start mihomo: %w", err)
	}

	waitCtx, cancel := context.WithTimeout(ctx, startupTimeout)
	defer cancel()
	if err := kernel.WaitForListener(waitCtx, fmt.Sprintf("127.0.0.1:%d", mixedPort)); err != nil {
		cmd.Process.Kill()
		cmd.Wait()
		os.RemoveAll(tmpDir)
		return "", nil, fmt.Errorf("waiting for mihomo listener: %w%s", err, stderrTail.Suffix())
	}

	stop := kernel.NewStopper(cmd, tmpDir)
	return fmt.Sprintf("socks5://127.0.0.1:%d", mixedPort), stop, nil
}

type mihomoConfig struct {
	Port               int          `yaml:"port,omitempty"`
	SocksPort          int          `yaml:"socks-port,omitempty"`
	MixedPort          int          `yaml:"mixed-port,omitempty"`
	AllowLan           bool         `yaml:"allow-lan,omitempty"`
	Mode               string       `yaml:"mode"`
	LogLevel           string       `yaml:"log-level"`
	Ipv6               bool         `yaml:"ipv6,omitempty"`
	ExternalController string       `yaml:"external-controller,omitempty"`
	Proxies            []proxyEntry `yaml:"proxies"`
	ProxyGroups        []proxyGroup `yaml:"proxy-groups"`
	Rules              []string     `yaml:"rules"`
	Dns                *dnsConfig   `yaml:"dns,omitempty"`
}

type proxyEntry map[string]any

type proxyGroup struct {
	Name    string   `yaml:"name"`
	Type    string   `yaml:"type"`
	Proxies []string `yaml:"proxies"`
}

type dnsConfig struct {
	Enable     bool     `yaml:"enable"`
	Nameserver []string `yaml:"nameserver"`
}

// mihomoType maps this tool's normalized type names back to mihomo's. mihomo
// rejects "shadowsocks" ("unsupport proxy type") and only accepts "ss".
func mihomoType(t string) string {
	switch strings.ToLower(t) {
	case "shadowsocks":
		return "ss"
	case "shadowsocksr":
		return "ssr"
	}
	return t
}

func buildConfig(proxy clash.Proxy, socksPort, httpPort, mixedPort int) ([]byte, error) {
	entry := make(proxyEntry)
	entry["name"] = proxy.Name
	entry["type"] = mihomoType(proxy.Type)
	entry["server"] = proxy.Server
	entry["port"] = proxy.Port

	switch strings.ToLower(proxy.Type) {
	case "vmess":
		entry["uuid"] = proxy.UUID
		entry["alterId"] = proxy.AlterID
		if proxy.Cipher != "" {
			entry["cipher"] = proxy.Cipher
		}
	case "vless":
		entry["uuid"] = proxy.UUID
		if proxy.Flow != "" {
			entry["flow"] = proxy.Flow
		}
	case "trojan":
		entry["password"] = proxy.Password
	case "shadowsocks", "ss":
		entry["password"] = proxy.Password
		entry["cipher"] = proxy.Cipher
	default:
		// hysteria2, tuic, wireguard, ssr, ...: mihomo understands them natively,
		// so forward credentials and every extra option untouched.
		if proxy.UUID != "" {
			entry["uuid"] = proxy.UUID
		}
		if proxy.Password != "" {
			entry["password"] = proxy.Password
		}
		if proxy.Cipher != "" {
			entry["cipher"] = proxy.Cipher
		}
		for k, v := range proxy.Extra {
			if _, exists := entry[k]; !exists {
				entry[k] = v
			}
		}
	}

	if proxy.Network != "" {
		entry["network"] = proxy.Network
	}
	if proxy.TLS {
		entry["tls"] = true
	}
	if proxy.SNI != "" {
		entry["sni"] = proxy.SNI
	}
	if proxy.SkipCertVerify {
		entry["skip-cert-verify"] = true
	}
	if proxy.WSOpts != nil {
		entry["ws-opts"] = map[string]any{
			"path": proxy.WSOpts.Path,
		}
		if proxy.WSOpts.Headers != nil {
			entry["ws-opts"].(map[string]any)["headers"] = proxy.WSOpts.Headers
		}
	}
	if proxy.RealityOpts != nil && proxy.RealityOpts.PublicKey != "" {
		entry["reality-opts"] = map[string]any{
			"public-key": proxy.RealityOpts.PublicKey,
			"short-id":   proxy.RealityOpts.ShortID,
		}
	}
	if proxy.ClientFingerprint != "" {
		entry["client-fingerprint"] = proxy.ClientFingerprint
	}

	cfg := mihomoConfig{
		SocksPort: socksPort,
		Port:      httpPort,
		MixedPort: mixedPort,
		AllowLan:  false,
		// "rule" + MATCH sends everything to the node under test. Do NOT use "direct":
		// it bypasses every proxy and silently measures the local network instead.
		Mode:     "rule",
		LogLevel: "silent",
		Ipv6:     false,
		Proxies:  []proxyEntry{entry},
		ProxyGroups: []proxyGroup{
			{
				Name:    "PROXY",
				Type:    "select",
				Proxies: []string{proxy.Name},
			},
		},
		Rules: []string{
			"MATCH,PROXY",
		},
		Dns: &dnsConfig{
			Enable:     true,
			Nameserver: []string{"https://1.1.1.1/dns-query", "https://8.8.8.8/dns-query"},
		},
	}

	return yaml.Marshal(cfg)
}

func DefaultBinaryName() string {
	if runtime.GOOS == "windows" {
		return "mihomo.exe"
	}
	return "mihomo"
}

// EnsureBinary finds a local mihomo binary or downloads the latest release automatically.
// downloadDir specifies where to place the downloaded binary (empty = exe directory).
func EnsureBinary(ctx context.Context, downloadDir string, timeout time.Duration) (string, error) {
	candidates := mihomoCandidates()

	// Check download directory first if specified
	if downloadDir != "" {
		for _, name := range candidates {
			full := filepath.Join(downloadDir, name)
			if info, err := os.Stat(full); err == nil && !info.IsDir() {
				return full, nil
			}
		}
	}

	exeDir := exeDir()
	if exeDir != "" {
		for _, name := range candidates {
			full := filepath.Join(exeDir, name)
			if info, err := os.Stat(full); err == nil && !info.IsDir() {
				return full, nil
			}
		}
	}
	for _, name := range candidates {
		if path, err := exec.LookPath(name); err == nil {
			return path, nil
		}
	}

	// Download from GitHub releases (serialized so concurrent workers don't corrupt the file)
	downloadMu.Lock()
	defer downloadMu.Unlock()
	if destDir := firstNonEmpty(downloadDir, exeDir, "."); true {
		for _, name := range candidates {
			full := filepath.Join(destDir, name)
			if info, err := os.Stat(full); err == nil && !info.IsDir() {
				return full, nil
			}
		}
	}
	rel, err := kernel.FetchRelease("MetaCubeX/mihomo", "latest")
	if err != nil {
		return "", err
	}
	asset, ok := selectAsset(rel.Assets, runtime.GOOS, runtime.GOARCH)
	if !ok {
		return "", fmt.Errorf("no release asset found for %s/%s", runtime.GOOS, runtime.GOARCH)
	}

	destDir := downloadDir
	if destDir == "" {
		destDir = exeDir
	}
	if destDir == "" {
		destDir = "."
	}
	binaryName := candidates[0]
	destPath := filepath.Join(destDir, binaryName)

	return downloadAndExtract(ctx, rel, asset, destPath, timeout)
}

func mihomoCandidates() []string {
	base := "mihomo"
	if runtime.GOOS == "windows" {
		return []string{base + ".exe"}
	}
	return []string{base}
}

func exeDir() string {
	if exe, err := os.Executable(); err == nil {
		return filepath.Dir(exe)
	}
	return ""
}

func selectAsset(assets []kernel.Asset, goos string, goarch string) (kernel.Asset, bool) {
	// Build platform key: e.g. "windows-amd64" -> "mihomo-windows-amd64"
	platKey := "mihomo-" + goos + "-" + goarch

	// Score each asset by how well it matches our platform
	type candidate struct {
		asset kernel.Asset
		score int
	}
	var best *candidate

	for _, a := range assets {
		name := strings.ToLower(a.Name)
		score := 0

		// Must contain our platform key
		if !strings.Contains(name, platKey) {
			continue
		}
		score += 100

		// Prefer "compatible" variant (widest compatibility)
		if strings.Contains(name, "compatible") {
			score += 50
		}

		// Prefer .zip for windows, .gz for unix
		if goos == "windows" && strings.HasSuffix(name, ".zip") {
			score += 20
		}
		if goos != "windows" && strings.HasSuffix(name, ".gz") {
			score += 20
		}

		// Prefer go125 (latest go version suffix in mihomo releases)
		if strings.Contains(name, "go125") {
			score += 10
		}

		// Prefer shorter names (no extra go version suffix = simpler)
		if !strings.Contains(name, "-go12") {
			score += 5
		}

		if best == nil || score > best.score {
			best = &candidate{asset: a, score: score}
		}
	}

	if best != nil {
		return best.asset, true
	}
	return kernel.Asset{}, false
}

func downloadAndExtract(ctx context.Context, rel *kernel.Release, asset kernel.Asset, destPath string, timeout time.Duration) (string, error) {
	archive, err := kernel.Download(ctx, rel, asset, destPath, timeout)
	if err != nil {
		return "", err
	}
	defer os.Remove(archive)

	extracted := destPath + ".extracted"
	defer os.Remove(extracted)
	if strings.HasSuffix(strings.ToLower(asset.Name), ".zip") {
		err = kernel.ExtractZip(archive, extracted, isMihomoBinary)
	} else {
		err = kernel.ExtractGzip(archive, extracted)
	}
	if err != nil {
		return "", fmt.Errorf("extract %s: %w", asset.Name, err)
	}
	if err := kernel.Activate(extracted, destPath); err != nil {
		return "", err
	}
	return destPath, nil
}

func isMihomoBinary(name string) bool {
	lower := strings.ToLower(name)
	if runtime.GOOS == "windows" {
		return strings.HasPrefix(lower, "mihomo") && strings.HasSuffix(lower, ".exe")
	}
	return strings.HasPrefix(lower, "mihomo") && !strings.HasSuffix(lower, ".exe") && !strings.HasSuffix(lower, ".gz") && !strings.HasSuffix(lower, ".zip")
}

func portOf(addr string) (int, error) {
	_, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(portStr)
}
