package mihomo

import (
	"archive/zip"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/anixops/speedtest/internal/clash"
	"gopkg.in/yaml.v3"
)

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

	socksPort, err := reservePort()
	if err != nil {
		return "", nil, err
	}
	httpPort, err := reservePort()
	if err != nil {
		return "", nil, err
	}
	mixedPort, err := reservePort()
	if err != nil {
		return "", nil, err
	}

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

	execPath := normalizePath(binaryPath)
	cmd := exec.CommandContext(ctx, execPath, "-d", tmpDir, "-f", configPath)
	cmd.Stdout = nil
	cmd.Stderr = nil
	if err := cmd.Start(); err != nil {
		os.RemoveAll(tmpDir)
		return "", nil, fmt.Errorf("failed to start mihomo: %w", err)
	}

	waitCtx, cancel := context.WithTimeout(ctx, startupTimeout)
	defer cancel()
	if err := waitForListener(waitCtx, fmt.Sprintf("127.0.0.1:%d", mixedPort)); err != nil {
		cmd.Process.Kill()
		cmd.Wait()
		os.RemoveAll(tmpDir)
		return "", nil, fmt.Errorf("waiting for mihomo listener: %w", err)
	}

	stop := makeStopper(cmd, tmpDir)
	return fmt.Sprintf("socks5://127.0.0.1:%d", mixedPort), stop, nil
}

type mihomoConfig struct {
	Port               int             `yaml:"port,omitempty"`
	SocksPort          int             `yaml:"socks-port,omitempty"`
	MixedPort          int             `yaml:"mixed-port,omitempty"`
	AllowLan           bool            `yaml:"allow-lan,omitempty"`
	Mode               string          `yaml:"mode"`
	LogLevel           string          `yaml:"log-level"`
	Ipv6               bool            `yaml:"ipv6,omitempty"`
	ExternalController string          `yaml:"external-controller,omitempty"`
	Proxies            []proxyEntry    `yaml:"proxies"`
	ProxyGroups        []proxyGroup    `yaml:"proxy-groups"`
	Rules              []string        `yaml:"rules"`
	Dns                *dnsConfig      `yaml:"dns,omitempty"`
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

func buildConfig(proxy clash.Proxy, socksPort, httpPort, mixedPort int) ([]byte, error) {
	entry := make(proxyEntry)
	entry["name"] = proxy.Name
	entry["type"] = proxy.Type
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
		Mode:      "direct",
		LogLevel:  "silent",
		Ipv6:      false,
		Proxies:   []proxyEntry{entry},
		ProxyGroups: []proxyGroup{
			{
				Name:    "PROXY",
				Type:    "select",
				Proxies: []string{proxy.Name},
			},
		},
		Rules: []string{
			"Match,PROXY",
		},
		Dns: &dnsConfig{
			Enable:     true,
			Nameserver: []string{"https://1.1.1.1/dns-query", "https://8.8.8.8/dns-query"},
		},
	}

	return yaml.Marshal(cfg)
}

func reservePort() (int, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, fmt.Errorf("reserve port: %w", err)
	}
	addr := ln.Addr().String()
	ln.Close()
	_, portStr, _ := net.SplitHostPort(addr)
	port, _ := strconv.Atoi(portStr)
	return port, nil
}

func waitForListener(ctx context.Context, addr string) error {
	var dialer net.Dialer
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		conn, err := dialer.DialContext(ctx, "tcp", addr)
		if err == nil {
			conn.Close()
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			continue
		}
	}
}

func makeStopper(cmd *exec.Cmd, cleanupDir string) func() error {
	var once sync.Once
	return func() error {
		var combined error
		once.Do(func() {
			if cmd.Process != nil {
				if err := cmd.Process.Kill(); err != nil {
					if !errorIs(err, os.ErrProcessDone) {
						combined = err
					}
				}
			}
			if err := cmd.Wait(); err != nil && !errorIs(err, context.Canceled) {
				if combined == nil {
					combined = err
				}
			}
			if err := os.RemoveAll(cleanupDir); err != nil {
				if combined == nil {
					combined = err
				}
			}
		})
		return combined
	}
}

func errorIs(err error, target error) bool {
	if err == nil || target == nil {
		return false
	}
	if err == target {
		return true
	}
	if e, ok := err.(*exec.ExitError); ok && e != nil {
		return false
	}
	return strings.Contains(err.Error(), target.Error())
}

func normalizePath(p string) string {
	p = strings.TrimSpace(p)
	if p == "" {
		return ""
	}
	if filepath.IsAbs(p) {
		return p
	}
	if strings.ContainsAny(p, `/\`) {
		return p
	}
	return "." + string(filepath.Separator) + p
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

	// Download from GitHub releases
	downloadURL, assetName, err := githubReleaseURL("MetaCubeX/mihomo", "latest")
	if err != nil {
		return "", err
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

	return downloadAndExtract(ctx, downloadURL, assetName, destPath, timeout)
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

func githubReleaseURL(repo string, version string) (string, string, error) {
	url := fmt.Sprintf("https://api.github.com/repos/%s/releases/%s", repo, version)

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return "", "", fmt.Errorf("fetch github release info: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("fetch github release info: status %s", resp.Status)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	if err != nil {
		return "", "", err
	}

	var release struct {
		TagName string `json:"tag_name"`
		Assets  []struct {
			Name        string `json:"name"`
			BrowserURL  string `json:"browser_download_url"`
			ContentType string `json:"content_type"`
		} `json:"assets"`
	}
	if err := json.Unmarshal(body, &release); err != nil {
		return "", "", fmt.Errorf("parse release info: %w", err)
	}

	assetName, dlURL := selectAsset(release.Assets, runtime.GOOS, runtime.GOARCH)
	if dlURL == "" {
		return "", "", fmt.Errorf("no release asset found for %s/%s", runtime.GOOS, runtime.GOARCH)
	}
	return dlURL, assetName, nil
}

func selectAsset(assets []struct {
	Name        string `json:"name"`
	BrowserURL  string `json:"browser_download_url"`
	ContentType string `json:"content_type"`
}, goos string, goarch string) (string, string) {
	// Build platform key: e.g. "windows-amd64" -> "mihomo-windows-amd64"
	platKey := "mihomo-" + goos + "-" + goarch

	// Score each asset by how well it matches our platform
	type candidate struct {
		index int
		name  string
		url   string
		score int
	}
	var best *candidate

	for i, a := range assets {
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
			best = &candidate{index: i, name: a.Name, url: a.BrowserURL, score: score}
		}
	}

	if best != nil {
		return best.name, best.url
	}
	return "", ""
}

func downloadAndExtract(ctx context.Context, downloadURL string, assetName string, destPath string, timeout time.Duration) (string, error) {
	fmt.Fprintf(os.Stderr, "Downloading %s...\n", assetName)

	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, downloadURL, nil)
	if err != nil {
		return "", fmt.Errorf("create download request: %w", err)
	}

	client := &http.Client{Timeout: timeout}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("download failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("download failed: status %s", resp.Status)
	}

	tmpPath := destPath + ".download"
	if err := os.MkdirAll(filepath.Dir(tmpPath), 0o755); err != nil {
		return "", err
	}
	tmpFile, err := os.Create(tmpPath)
	if err != nil {
		return "", err
	}

	written, err := io.Copy(tmpFile, resp.Body)
	tmpFile.Close()
	if err != nil {
		os.Remove(tmpPath)
		return "", fmt.Errorf("write download: %w", err)
	}
	if written == 0 {
		os.Remove(tmpPath)
		return "", errors.New("downloaded file is empty")
	}

	// Extract if it's a zip/gz
	extractedPath := destPath + ".extracted"
	if err := extractAsset(tmpPath, extractedPath); err != nil {
		// If extraction fails, assume it's a raw binary
		os.Remove(extractedPath)
		extractedPath = tmpPath
	}

	if runtime.GOOS == "windows" {
		os.Remove(destPath)
	}
	if err := os.Rename(extractedPath, destPath); err != nil {
		os.Remove(extractedPath)
		if copyErr := copyFile(extractedPath, destPath); copyErr != nil {
			return "", fmt.Errorf("activate binary: %w", copyErr)
		}
	}
	os.Remove(tmpPath)
	os.Remove(extractedPath)

	if err := os.Chmod(destPath, 0o755); err != nil {
		return "", err
	}
	return destPath, nil
}

func extractAsset(srcPath string, destPath string) error {
	// Try zip first
	if r, err := zip.OpenReader(srcPath); err == nil {
		defer r.Close()
		for _, f := range r.File {
			name := filepath.Base(f.Name)
			// Look for the mihomo binary (with or without .exe)
			if isMihomoBinary(name) {
				src, err := f.Open()
				if err != nil {
					return err
				}
				defer src.Close()
				dst, err := os.OpenFile(destPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o755)
				if err != nil {
					return err
				}
				if _, err := io.Copy(dst, src); err != nil {
					dst.Close()
					return err
				}
				return dst.Close()
			}
		}
		return errors.New("no mihomo binary found in zip")
	}

	// Try gz decompression
	if strings.HasSuffix(strings.ToLower(srcPath), ".gz") {
		f, err := os.Open(srcPath)
		if err != nil {
			return err
		}
		defer f.Close()
		gr, err := gzip.NewReader(f)
		if err != nil {
			return err
		}
		defer gr.Close()

		out, err := os.OpenFile(destPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o755)
		if err != nil {
			return err
		}
		if _, err := io.Copy(out, gr); err != nil {
			out.Close()
			return err
		}
		return out.Close()
	}

	return errors.New("not a supported archive format")
}

func isMihomoBinary(name string) bool {
	lower := strings.ToLower(name)
	if runtime.GOOS == "windows" {
		return strings.HasPrefix(lower, "mihomo") && strings.HasSuffix(lower, ".exe")
	}
	return strings.HasPrefix(lower, "mihomo") && !strings.HasSuffix(lower, ".exe") && !strings.HasSuffix(lower, ".gz") && !strings.HasSuffix(lower, ".zip")
}

func copyFile(src string, dst string) error {
	sf, err := os.Open(src)
	if err != nil {
		return err
	}
	defer sf.Close()
	df, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer df.Close()
	_, err = io.Copy(df, sf)
	return err
}
