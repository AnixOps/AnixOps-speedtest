package xray

import (
	"encoding/json"
	"github.com/anixops/speedtest/internal/kernel"
	"strings"
	"testing"
)

func build(t *testing.T, n NodeConfig) map[string]any {
	t.Helper()
	b, err := BuildConfigJSON(n, "127.0.0.1:10808")
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, b)
	}
	return m
}

func outbound0(m map[string]any) map[string]any { return m["outbounds"].([]any)[0].(map[string]any) }

func TestBuildConfigVlessReality(t *testing.T) {
	m := build(t, NodeConfig{
		Protocol: "vless", Address: "1.2.3.4", Port: 443, UUID: "u", Flow: "xtls-rprx-vision",
		ServerName: "www.example.com", RealityPublicKey: "PK", RealityShortID: "ab", ClientFingerprint: "chrome",
	})
	ob := outbound0(m)
	if ob["protocol"] != "vless" {
		t.Fatalf("protocol: %v", ob["protocol"])
	}
	ss := ob["streamSettings"].(map[string]any)
	if ss["security"] != "reality" {
		t.Fatalf("security: %v", ss["security"])
	}
	rs := ss["realitySettings"].(map[string]any)
	if rs["publicKey"] != "PK" || rs["shortId"] != "ab" || rs["fingerprint"] != "chrome" {
		t.Fatalf("reality settings: %v", rs)
	}
	in := m["inbounds"].([]any)[0].(map[string]any)
	if in["protocol"] != "socks" || int(in["port"].(float64)) != 10808 {
		t.Fatalf("inbound: %v", in)
	}
}

func TestBuildConfigWebSocketTLS(t *testing.T) {
	m := build(t, NodeConfig{Protocol: "vmess", Address: "h.com", Port: 443, UUID: "u", Network: "ws", TLS: true, ServerName: "h.com", WSPath: "/p", WSHost: "cdn.h.com"})
	ss := outbound0(m)["streamSettings"].(map[string]any)
	if ss["network"] != "ws" || ss["security"] != "tls" {
		t.Fatalf("stream: %v", ss)
	}
	ws := ss["wsSettings"].(map[string]any)
	if ws["path"] != "/p" || ws["headers"].(map[string]any)["Host"] != "cdn.h.com" {
		t.Fatalf("ws: %v", ws)
	}
}

func TestBuildConfigAllProtocols(t *testing.T) {
	cases := []NodeConfig{
		{Protocol: "vmess", UUID: "u"},
		{Protocol: "vless", UUID: "u"},
		{Protocol: "trojan", Password: "p"},
		{Protocol: "shadowsocks", Password: "p", Cipher: "aes-256-gcm"},
		{Protocol: "ss", Password: "p", Cipher: "aes-256-gcm"},
	}
	for _, c := range cases {
		c.Address, c.Port = "a.com", 443
		if outbound0(build(t, c)) == nil {
			t.Errorf("%s: no outbound", c.Protocol)
		}
	}
}

func TestBuildConfigValidation(t *testing.T) {
	bad := map[string]NodeConfig{
		"no address":   {Protocol: "vmess", Port: 1, UUID: "u"},
		"bad port":     {Protocol: "vmess", Address: "a", Port: 70000, UUID: "u"},
		"no protocol":  {Address: "a", Port: 1},
		"vmess no id":  {Protocol: "vmess", Address: "a", Port: 1},
		"trojan no pw": {Protocol: "trojan", Address: "a", Port: 1},
		"ss no cipher": {Protocol: "shadowsocks", Address: "a", Port: 1, Password: "p"},
		"unknown":      {Protocol: "wireguard", Address: "a", Port: 1},
	}
	for name, n := range bad {
		if _, err := BuildConfigJSON(n, "127.0.0.1:1080"); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
	if _, err := BuildConfigJSON(NodeConfig{Protocol: "vmess", Address: "a", Port: 1, UUID: "u"}, "bad"); err == nil || !strings.Contains(err.Error(), "socks listen") {
		t.Errorf("bad listen address: %v", err)
	}
}

func TestSelectAsset(t *testing.T) {
	assets := []kernel.Asset{{Name: "Xray-linux-64.zip"}, {Name: "Xray-macos-arm64-v8a.zip"}, {Name: "Xray-linux-64.zip.dgst"}}
	if a, ok := selectAsset(assets, "linux", "amd64"); !ok || a.Name != "Xray-linux-64.zip" {
		t.Errorf("linux/amd64: %v %v", a, ok)
	}
	if a, ok := selectAsset(assets, "darwin", "arm64"); !ok || a.Name != "Xray-macos-arm64-v8a.zip" {
		t.Errorf("darwin/arm64: %v %v", a, ok)
	}
}
