package mihomo

import (
	"github.com/anixops/speedtest/internal/clash"
	"gopkg.in/yaml.v3"
	"testing"

	"github.com/anixops/speedtest/internal/kernel"
)

func TestSelectAssetPrefersCompatibleGz(t *testing.T) {
	assets := []kernel.Asset{
		{Name: "mihomo-linux-amd64-v1.19.0.gz"},
		{Name: "mihomo-linux-amd64-compatible-v1.19.0.gz"},
		{Name: "mihomo-linux-arm64-v1.19.0.gz"},
		{Name: "mihomo-windows-amd64-compatible-v1.19.0.zip"},
	}
	a, ok := selectAsset(assets, "linux", "amd64")
	if !ok || a.Name != "mihomo-linux-amd64-compatible-v1.19.0.gz" {
		t.Fatalf("got %v %v", a, ok)
	}
	if a, ok := selectAsset(assets, "windows", "amd64"); !ok || a.Name != "mihomo-windows-amd64-compatible-v1.19.0.zip" {
		t.Fatalf("windows: %v %v", a, ok)
	}
	if _, ok := selectAsset(assets, "plan9", "amd64"); ok {
		t.Fatal("unsupported platform must not match")
	}
}

func TestBuildConfigForwardsExtraOptions(t *testing.T) {
	p := clash.Proxy{
		Name: "h", Type: "hysteria2", Server: "h.com", Port: 443, Password: "pw", SNI: "h.com",
		Extra: map[string]any{"obfs": "salamander", "obfs-password": "op", "name": "must-not-override"},
	}
	out, err := buildConfig(p, 1, 2, 3)
	if err != nil {
		t.Fatal(err)
	}
	var cfg struct {
		Proxies []map[string]any `yaml:"proxies"`
	}
	if err := yaml.Unmarshal(out, &cfg); err != nil {
		t.Fatal(err)
	}
	e := cfg.Proxies[0]
	if e["type"] != "hysteria2" || e["password"] != "pw" || e["obfs"] != "salamander" || e["name"] != "h" {
		t.Fatalf("entry: %v", e)
	}
}

func TestBuildConfigRoutesThroughProxy(t *testing.T) {
	out, err := buildConfig(clash.Proxy{Name: "n", Type: "ss", Server: "s", Port: 1, Cipher: "aes-256-gcm", Password: "p"}, 1, 2, 3)
	if err != nil {
		t.Fatal(err)
	}
	var cfg struct {
		Mode  string   `yaml:"mode"`
		Rules []string `yaml:"rules"`
	}
	if err := yaml.Unmarshal(out, &cfg); err != nil {
		t.Fatal(err)
	}
	// Regression: mode "direct" bypassed the proxy and measured the local network.
	if cfg.Mode != "rule" || len(cfg.Rules) != 1 || cfg.Rules[0] != "MATCH,PROXY" {
		t.Fatalf("traffic would not be routed through the node: mode=%q rules=%v", cfg.Mode, cfg.Rules)
	}
}

func TestBuildConfigShadowsocksTypeName(t *testing.T) {
	// Regression: mihomo fails to start with type "shadowsocks"; it requires "ss".
	for _, typ := range []string{"shadowsocks", "ss"} {
		out, err := buildConfig(clash.Proxy{Name: "n", Type: typ, Server: "s", Port: 1, Cipher: "aes-256-gcm", Password: "p"}, 1, 2, 3)
		if err != nil {
			t.Fatal(err)
		}
		var cfg struct {
			Proxies []map[string]any `yaml:"proxies"`
		}
		if err := yaml.Unmarshal(out, &cfg); err != nil {
			t.Fatal(err)
		}
		if got := cfg.Proxies[0]["type"]; got != "ss" {
			t.Errorf("%s: emitted type %v, want ss", typ, got)
		}
	}
}
