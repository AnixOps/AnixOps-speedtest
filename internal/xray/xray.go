package xray

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/anixops/speedtest/internal/kernel"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	downloadMu sync.Mutex
)

type NodeConfig struct {
	Protocol          string
	Address           string
	Port              int
	Network           string
	UUID              string
	Password          string
	Cipher            string
	Flow              string
	Security          string
	TLS               bool
	ServerName        string
	WSPath            string
	WSHost            string
	RealityPublicKey  string
	RealityShortID    string
	ClientFingerprint string
}

func BuildConfigJSON(node NodeConfig, socksListen string) ([]byte, error) {
	nodeAddr := strings.TrimSpace(node.Address)
	if nodeAddr == "" {
		return nil, errors.New("node address is required")
	}
	if node.Port <= 0 || node.Port > 65535 {
		return nil, fmt.Errorf("node port must be between 1 and 65535, got %d", node.Port)
	}
	proto := strings.ToLower(strings.TrimSpace(node.Protocol))
	if proto == "" {
		return nil, errors.New("node protocol is required")
	}
	network := strings.ToLower(strings.TrimSpace(node.Network))
	if network == "" {
		network = "tcp"
	}

	nodeOutbound, err := buildOutbound(nodeAddr, node.Port, proto, network, node)
	if err != nil {
		return nil, err
	}

	socksHost, socksPort, err := parseHostPort(socksListen)
	if err != nil {
		return nil, err
	}

	cfg := configRoot{
		Log:       logConfig{LogLevel: "warning"},
		Inbounds:  []inbound{buildSocksInbound(socksHost, socksPort)},
		Outbounds: []outbound{nodeOutbound},
	}

	return json.MarshalIndent(cfg, "", "  ")
}

func Start(ctx context.Context, binaryPath string, node NodeConfig, workDir string, startupTimeout time.Duration) (string, func() error, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	binaryPath = strings.TrimSpace(binaryPath)
	if binaryPath == "" {
		return "", nil, errors.New("binaryPath is required")
	}
	if startupTimeout <= 0 {
		return "", nil, fmt.Errorf("startup timeout must be > 0, got %s", startupTimeout)
	}

	socksAddr, err := kernel.ReservePort()
	if err != nil {
		return "", nil, err
	}

	if workDir != "" {
		if err := os.MkdirAll(workDir, 0o755); err != nil {
			return "", nil, fmt.Errorf("failed to prepare workDir: %w", err)
		}
	}
	tmpDir, err := os.MkdirTemp(workDir, "speedtest-xray-config-")
	if err != nil {
		return "", nil, fmt.Errorf("failed to create temp dir: %w", err)
	}

	configBytes, err := BuildConfigJSON(node, socksAddr)
	if err != nil {
		os.RemoveAll(tmpDir)
		return "", nil, err
	}

	configPath := filepath.Join(tmpDir, "config.json")
	if err := os.WriteFile(configPath, configBytes, 0o600); err != nil {
		os.RemoveAll(tmpDir)
		return "", nil, fmt.Errorf("failed to write config: %w", err)
	}

	execPath := kernel.ExecPath(binaryPath)
	cmd := exec.CommandContext(ctx, execPath, "-c", configPath)
	cmd.Stdout = nil
	cmd.Stderr = nil
	if err := cmd.Start(); err != nil {
		os.RemoveAll(tmpDir)
		return "", nil, fmt.Errorf("failed to start xray-core: %w", err)
	}

	waitCtx, cancel := context.WithTimeout(ctx, startupTimeout)
	defer cancel()
	if err := kernel.WaitForListener(waitCtx, socksAddr); err != nil {
		cmd.Process.Kill()
		cmd.Wait()
		os.RemoveAll(tmpDir)
		return "", nil, fmt.Errorf("waiting for socks listener: %w", err)
	}

	stop := kernel.NewStopper(cmd, tmpDir)
	return "socks5://" + socksAddr, stop, nil
}

func parseHostPort(listen string) (string, int, error) {
	if listen == "" {
		return "", 0, errors.New("socks listen address is required")
	}
	host, portStr, err := net.SplitHostPort(listen)
	if err != nil {
		return "", 0, fmt.Errorf("invalid socks listen %q: %w", listen, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return "", 0, fmt.Errorf("invalid socks listen port %q: %w", portStr, err)
	}
	if host == "" {
		host = "0.0.0.0"
	}
	return host, port, nil
}

func DefaultBinaryName() string {
	if runtime.GOOS == "windows" {
		return "xray-core.exe"
	}
	return "xray-core"
}

// --- JSON config types ---

type configRoot struct {
	Log       logConfig  `json:"log"`
	Inbounds  []inbound  `json:"inbounds"`
	Outbounds []outbound `json:"outbounds"`
}

type logConfig struct {
	LogLevel string `json:"loglevel"`
}

type inbound struct {
	Listen   string        `json:"listen"`
	Port     int           `json:"port"`
	Protocol string        `json:"protocol"`
	Settings socksSettings `json:"settings"`
	Tag      string        `json:"tag"`
}

type socksSettings struct {
	Auth string `json:"auth"`
	UDP  bool   `json:"udp"`
	IP   string `json:"ip"`
}

func buildSocksInbound(host string, port int) inbound {
	return inbound{
		Listen:   host,
		Port:     port,
		Protocol: "socks",
		Tag:      "local-socks",
		Settings: socksSettings{Auth: "noauth", UDP: true, IP: host},
	}
}

type outbound struct {
	Protocol       string          `json:"protocol"`
	Settings       interface{}     `json:"settings"`
	StreamSettings *streamSettings `json:"streamSettings,omitempty"`
}

type streamSettings struct {
	Network         string           `json:"network"`
	Security        string           `json:"security,omitempty"`
	WSSettings      *wsSettings      `json:"wsSettings,omitempty"`
	TLSSettings     *tlsSettings     `json:"tlsSettings,omitempty"`
	RealitySettings *realitySettings `json:"realitySettings,omitempty"`
}

type wsSettings struct {
	Path    string            `json:"path,omitempty"`
	Headers map[string]string `json:"headers,omitempty"`
}

type tlsSettings struct {
	AllowInsecure bool   `json:"allowInsecure"`
	ServerName    string `json:"serverName,omitempty"`
}

type realitySettings struct {
	ServerName  string `json:"serverName"`
	PublicKey   string `json:"publicKey"`
	ShortID     string `json:"shortId,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`
}

func buildStreamSettings(network string, node NodeConfig) *streamSettings {
	s := &streamSettings{Network: network}
	if network == "ws" {
		s.WSSettings = &wsSettings{Path: node.WSPath}
		headers := make(map[string]string)
		if strings.TrimSpace(node.WSHost) != "" {
			headers["Host"] = node.WSHost
		}
		if len(headers) > 0 {
			s.WSSettings.Headers = headers
		}
	}
	if node.RealityPublicKey != "" {
		s.Security = "reality"
		s.RealitySettings = &realitySettings{
			ServerName:  node.ServerName,
			PublicKey:   node.RealityPublicKey,
			ShortID:     node.RealityShortID,
			Fingerprint: node.ClientFingerprint,
		}
	} else if node.TLS {
		s.Security = "tls"
		s.TLSSettings = &tlsSettings{AllowInsecure: true}
		if strings.TrimSpace(node.ServerName) != "" {
			s.TLSSettings.ServerName = node.ServerName
		}
	}
	return s
}

func buildOutbound(address string, port int, protocol, network string, node NodeConfig) (outbound, error) {
	stream := buildStreamSettings(network, node)
	switch protocol {
	case "vmess":
		if strings.TrimSpace(node.UUID) == "" {
			return outbound{}, errors.New("vmess node requires UUID")
		}
		security := strings.TrimSpace(node.Security)
		if security == "" {
			security = "auto"
		}
		return outbound{
			Protocol: "vmess",
			Settings: vmessSettings{Vnext: []vmessVnext{{
				Address: address,
				Port:    port,
				Users: []vmessUser{{
					ID:       node.UUID,
					AlterID:  0,
					Security: security,
				}},
			}}},
			StreamSettings: stream,
		}, nil
	case "vless":
		if strings.TrimSpace(node.UUID) == "" {
			return outbound{}, errors.New("vless node requires UUID")
		}
		user := vlessUser{ID: node.UUID, Encryption: "none"}
		if flow := strings.TrimSpace(node.Flow); flow != "" {
			user.Flow = flow
		}
		return outbound{
			Protocol: "vless",
			Settings: vlessSettings{Vnext: []vlessVnext{{
				Address: address,
				Port:    port,
				Users:   []vlessUser{user},
			}}},
			StreamSettings: stream,
		}, nil
	case "trojan":
		if strings.TrimSpace(node.Password) == "" {
			return outbound{}, errors.New("trojan node requires password")
		}
		return outbound{
			Protocol:       "trojan",
			Settings:       trojanSettings{Servers: []trojanServer{{Address: address, Port: port, Password: node.Password}}},
			StreamSettings: stream,
		}, nil
	case "shadowsocks", "ss":
		if strings.TrimSpace(node.Password) == "" {
			return outbound{}, errors.New("shadowsocks node requires password")
		}
		cipher := strings.TrimSpace(node.Cipher)
		if cipher == "" {
			return outbound{}, errors.New("shadowsocks node requires cipher")
		}
		return outbound{
			Protocol:       "shadowsocks",
			Settings:       ssSettings{Servers: []ssServer{{Address: address, Port: port, Method: cipher, Password: node.Password}}},
			StreamSettings: stream,
		}, nil
	default:
		return outbound{}, fmt.Errorf("unsupported node protocol %q", protocol)
	}
}

type vmessSettings struct {
	Vnext []vmessVnext `json:"vnext"`
}

type vmessVnext struct {
	Address string      `json:"address"`
	Port    int         `json:"port"`
	Users   []vmessUser `json:"users"`
}

type vmessUser struct {
	ID       string `json:"id"`
	AlterID  int    `json:"alterId"`
	Security string `json:"security"`
}

type vlessSettings struct {
	Vnext []vlessVnext `json:"vnext"`
}

type vlessVnext struct {
	Address string      `json:"address"`
	Port    int         `json:"port"`
	Users   []vlessUser `json:"users"`
}

type vlessUser struct {
	ID         string `json:"id"`
	Flow       string `json:"flow,omitempty"`
	Encryption string `json:"encryption"`
}

type trojanSettings struct {
	Servers []trojanServer `json:"servers"`
}

type trojanServer struct {
	Address  string `json:"address"`
	Port     int    `json:"port"`
	Password string `json:"password"`
}

type ssSettings struct {
	Servers []ssServer `json:"servers"`
}

type ssServer struct {
	Address  string `json:"address"`
	Port     int    `json:"port"`
	Method   string `json:"method"`
	Password string `json:"password"`
	OTA      bool   `json:"ota"`
}

// EnsureBinary finds a local xray-core binary or downloads the latest release automatically.
// downloadDir specifies where to place the downloaded binary (empty = exe directory).
func EnsureBinary(ctx context.Context, downloadDir string, timeout time.Duration) (string, error) {
	// 1. Check download directory first if specified
	candidates := binaryCandidates()
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
	// 2. Check PATH
	for _, name := range candidates {
		if path, err := exec.LookPath(name); err == nil {
			return path, nil
		}
	}

	// 3. Download from GitHub releases (mutex to prevent concurrent download corruption)
	downloadMu.Lock()
	defer downloadMu.Unlock()

	// Double-check after acquiring lock — another goroutine may have downloaded it
	destDir := downloadDir
	if destDir == "" {
		destDir = exeDir
	}
	if destDir == "" {
		destDir = "."
	}
	for _, name := range candidates {
		full := filepath.Join(destDir, name)
		if info, err := os.Stat(full); err == nil && !info.IsDir() {
			return full, nil
		}
	}

	rel, err := kernel.FetchRelease("XTLS/Xray-core", "latest")
	if err != nil {
		return "", err
	}
	asset, ok := selectAsset(rel.Assets, runtime.GOOS, runtime.GOARCH)
	if !ok {
		return "", fmt.Errorf("no release asset found for %s/%s", runtime.GOOS, runtime.GOARCH)
	}

	binaryName := candidates[0]
	destPath := filepath.Join(destDir, binaryName)

	return downloadAndExtract(ctx, rel, asset, destPath, timeout)
}

func binaryCandidates() []string {
	if runtime.GOOS == "windows" {
		return []string{"xray-core.exe", "xray.exe"}
	}
	return []string{"xray-core", "xray"}
}

func exeDir() string {
	if exe, err := os.Executable(); err == nil {
		return filepath.Dir(exe)
	}
	return ""
}

func selectAsset(assets []kernel.Asset, goos string, goarch string) (kernel.Asset, bool) {
	assetPatterns := map[string][]string{
		"linux-amd64":   {"Xray-linux-64.zip"},
		"linux-arm64":   {"Xray-linux-arm64-v8a.zip"},
		"linux-armv7":   {"Xray-linux-arm32-v7a.zip"},
		"darwin-amd64":  {"Xray-macos-64.zip"},
		"darwin-arm64":  {"Xray-macos-arm64-v8a.zip"},
		"windows-amd64": {"Xray-windows-64.zip"},
		"windows-arm64": {"Xray-windows-arm64-v8a.zip"},
		"windows-386":   {"Xray-windows-32.zip"},
	}

	key := goos + "-" + goarch
	if patterns, ok := assetPatterns[key]; ok {
		for _, a := range assets {
			for _, pat := range patterns {
				if strings.EqualFold(a.Name, pat) {
					return a, true
				}
			}
		}
	}

	// Fallback: first zip asset
	for _, a := range assets {
		if strings.HasSuffix(a.Name, ".zip") {
			return a, true
		}
	}
	return kernel.Asset{}, false
}

func downloadAndExtract(ctx context.Context, rel *kernel.Release, asset kernel.Asset, destPath string, timeout time.Duration) (string, error) {
	archive, err := kernel.Download(ctx, rel, asset, destPath, timeout)
	if err != nil {
		return "", err
	}
	defer os.Remove(archive)

	binarySet := make(map[string]struct{})
	for _, n := range binaryCandidates() {
		binarySet[strings.ToLower(n)] = struct{}{}
	}
	extracted := destPath + ".extracted"
	defer os.Remove(extracted)
	if err := kernel.ExtractZip(archive, extracted, func(name string) bool {
		_, ok := binarySet[strings.ToLower(name)]
		return ok
	}); err != nil {
		return "", fmt.Errorf("extract zip: %w", err)
	}
	if err := kernel.Activate(extracted, destPath); err != nil {
		return "", err
	}
	return destPath, nil
}
