package clash

import "testing"

func TestParseNormalizesAndFilters(t *testing.T) {
	y := []byte(`
proxies:
  - {name: a, type: ss, server: a.com, port: 8388, cipher: aes-256-gcm, password: pw}
  - {name: b, type: vless, server: b.com, port: 443, uuid: u, flow: xtls-rprx-vision, reality-opts: {public-key: PK, short-id: ab}}
  - {name: "", type: vmess, server: c.com, port: 1}
  - {name: d, type: vmess, server: "", port: 1}
  - {name: e, type: vmess, server: e.com, port: 0}
`)
	ps, err := Parse(y)
	if err != nil {
		t.Fatal(err)
	}
	if len(ps) != 2 {
		t.Fatalf("got %d proxies, want 2", len(ps))
	}
	if ps[0].Type != "shadowsocks" {
		t.Errorf("ss should normalize to shadowsocks, got %q", ps[0].Type)
	}
	if ps[1].RealityOpts == nil || ps[1].RealityOpts.PublicKey != "PK" || ps[1].Flow != "xtls-rprx-vision" {
		t.Errorf("reality fields lost: %+v", ps[1])
	}
}

func TestParseErrors(t *testing.T) {
	if _, err := Parse([]byte("proxies: []")); err == nil {
		t.Error("empty proxy list must error")
	}
	if _, err := Parse([]byte("proxies: [")); err == nil {
		t.Error("invalid yaml must error")
	}
	if _, err := ParseFile("/nonexistent/x.yaml"); err == nil {
		t.Error("missing file must error")
	}
}
