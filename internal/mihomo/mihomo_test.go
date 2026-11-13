package mihomo

import (
	"github.com/anixops/speedtest/internal/clash"
	"gopkg.in/yaml.v3"
	"reflect"
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

// A lost gRPC service name or ALPN makes a valid Trojan node appear unreachable.
// Cover both the single-node and batch renderers: both use buildEntry.
func TestTrojanGRPCTransportRoundTripSingleAndBatch(t *testing.T) {
	source := []byte(`proxies:
  - name: grpc-test
    type: trojan
    server: example.invalid
    port: 443
    password: fixture-only
    network: grpc
    tls: true
    sni: test.example.invalid
    grpc-opts:
      grpc-service-name: important-service-name
    alpn: [h2, http/1.1]
    client-fingerprint: chrome
    udp: true
`)
	proxies, err := clash.Parse(source)
	if err != nil || len(proxies) != 1 {
		t.Fatalf("parse synthetic source: %v", err)
	}
	check := func(t *testing.T, raw []byte) {
		t.Helper()
		var doc struct {
			Proxies []map[string]any `yaml:"proxies"`
		}
		if err := yaml.Unmarshal(raw, &doc); err != nil {
			t.Fatal(err)
		}
		if len(doc.Proxies) != 1 {
			t.Fatalf("proxy count: %d", len(doc.Proxies))
		}
		got := doc.Proxies[0]
		want := map[string]any{}
		var input struct {
			Proxies []map[string]any `yaml:"proxies"`
		}
		if err := yaml.Unmarshal(source, &input); err != nil {
			t.Fatal(err)
		}
		for k, v := range input.Proxies[0] {
			want[k] = v
		}
		// A batch renderer is expected to use an internal unique name.
		delete(got, "name")
		delete(want, "name")
		for k, v := range want {
			if !reflect.DeepEqual(got[k], v) {
				t.Errorf("transport option %q lost or changed: got=%v want=%v", k, got[k], v)
			}
		}
	}
	t.Run("single", func(t *testing.T) {
		raw, err := buildConfig(proxies[0], 1101, 1102, 1103)
		if err != nil {
			t.Fatal(err)
		}
		check(t, raw)
	})
	t.Run("batch", func(t *testing.T) {
		raw, err := buildBatchConfig(proxies, []int{1104})
		if err != nil {
			t.Fatal(err)
		}
		check(t, raw)
	})
}

// Known proxy types must preserve generic Clash options, but arbitrary raw
// extras may never override the trusted normalized name or credentials.
func TestTrojanExtraCannotOverrideIdentity(t *testing.T) {
	got := buildEntry(clash.Proxy{
		Name: "canonical-node", Type: "trojan", Server: "example.invalid", Port: 443,
		Password: "canonical-fixture", Extra: map[string]any{
			"name": "different-node", "password": "different-fixture",
			"alpn":               []string{"h2"},
			"client-fingerprint": "chrome",
		},
	}, "internal-node")
	if got["name"] != "internal-node" || got["password"] != "canonical-fixture" {
		t.Fatalf("generic Clash options overrode core identity: %+v", got)
	}
	if _, ok := got["alpn"]; !ok {
		t.Fatal("ALPN lost for trojan")
	}
	if _, ok := got["client-fingerprint"]; !ok {
		t.Fatal("fingerprint lost for trojan")
	}
}

func TestTrojanH2OptsArePreserved(t *testing.T) {
	p := clash.Proxy{
		Name: "h2-node", Type: "trojan", Server: "example.invalid", Port: 443,
		Password: "fixture", Network: "h2",
		H2Opts: &clash.H2Options{Host: []string{"edge.example.invalid"}, Path: "/h2"},
	}
	out, err := buildConfig(p, 1201, 1202, 1203)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Proxies []map[string]any `yaml:"proxies"`
	}
	if err := yaml.Unmarshal(out, &doc); err != nil {
		t.Fatal(err)
	}
	h2, ok := doc.Proxies[0]["h2-opts"].(map[string]any)
	if !ok {
		t.Fatalf("missing H2 options: %v", doc.Proxies[0])
	}
	if h2["path"] != "/h2" {
		t.Fatalf("H2 path changed: %v", h2)
	}
}
