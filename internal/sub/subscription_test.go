package sub

import (
	"encoding/base64"
	"testing"
)

func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

func TestParseVmessStringAndNumericPort(t *testing.T) {
	for _, port := range []string{`"443"`, `443`} {
		payload := `{"ps":"HK 01","add":"hk.example.com","port":` + port + `,"id":"uuid-1","scy":"auto","net":"ws","host":"h.example.com","path":"/ws","tls":"tls","sni":"s.example.com"}`
		n, err := parseLine("vmess://" + b64(payload))
		if err != nil {
			t.Fatalf("port %s: %v", port, err)
		}
		if n.Server != "hk.example.com" || n.Port != "443" || n.UUID != "uuid-1" || n.Network != "ws" || n.Method != "auto" || n.Name != "HK 01" {
			t.Fatalf("port %s: unexpected node %+v", port, n)
		}
	}
}

func TestParseVlessReality(t *testing.T) {
	link := "vless://uuid-2@1.2.3.4:443?type=tcp&security=reality&sni=www.microsoft.com&fp=chrome&pbk=PUBKEY&sid=ab12&flow=xtls-rprx-vision#JP%20Reality"
	n, err := parseLine(link)
	if err != nil {
		t.Fatal(err)
	}
	if n.TLS != "reality" || n.RealityPublicKey != "PUBKEY" || n.RealityShortID != "ab12" ||
		n.ClientFingerprint != "chrome" || n.Flow != "xtls-rprx-vision" || n.Name != "JP Reality" || n.SNI != "www.microsoft.com" {
		t.Fatalf("unexpected node %+v", n)
	}
}

func TestParseTrojan(t *testing.T) {
	n, err := parseLine("trojan://pa%24%24@t.example.com:8443?sni=t.example.com&type=ws&path=%2Fp#T1")
	if err != nil {
		t.Fatal(err)
	}
	if n.Password != "pa$$" || n.Port != "8443" || n.Network != "ws" || n.Path != "/p" || n.Name != "T1" {
		t.Fatalf("unexpected node %+v", n)
	}
}

func TestParseShadowsocksForms(t *testing.T) {
	cases := map[string]string{
		"sip002": "ss://" + base64.RawURLEncoding.EncodeToString([]byte("aes-256-gcm:pw")) + "@s.example.com:8388#SS1",
		"legacy": "ss://" + b64("aes-256-gcm:pw@s.example.com:8388") + "#SS1",
		"plain":  "ss://aes-256-gcm:pw@s.example.com:8388#SS1",
	}
	for name, link := range cases {
		n, err := parseLine(link)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if n.Method != "aes-256-gcm" || n.Password != "pw" || n.Server != "s.example.com" || n.Port != "8388" || n.Name != "SS1" {
			t.Fatalf("%s: unexpected node %+v", name, n)
		}
	}
}

func TestParseLineRejectsUnsupported(t *testing.T) {
	for _, l := range []string{"http://x", "hysteria2://x", "", "vmess://", "ss://"} {
		if _, err := parseLine(l); err == nil && l != "hysteria2://x" {
			t.Errorf("%q should fail", l)
		}
	}
}

func TestParseSubscriptionSkipsBadLines(t *testing.T) {
	content := "garbage\r\ntrojan://p@a.com:443#A\r\n\r\nvless://u@b.com:443#B\n"
	if got := len(parseSubscription(content)); got != 2 {
		t.Fatalf("got %d nodes, want 2", got)
	}
}

func TestParseClashYAML(t *testing.T) {
	y := `
proxies:
  - {name: a, type: vmess, server: a.com, port: 443, uuid: u1, network: ws, tls: true}
  - {name: "", type: ss, server: b.com, port: 1}
  - {name: c, type: trojan, server: c.com, port: 443, password: pw}
`
	nodes := parseClashYAML(y)
	if len(nodes) != 2 || nodes[0].Name != "a" || nodes[1].Password != "pw" {
		t.Fatalf("unexpected %+v", nodes)
	}
}

func TestDecodeBase64Variants(t *testing.T) {
	want := "hello?>"
	for _, enc := range []string{
		base64.StdEncoding.EncodeToString([]byte(want)),
		base64.RawStdEncoding.EncodeToString([]byte(want)),
		base64.URLEncoding.EncodeToString([]byte(want)),
		base64.RawURLEncoding.EncodeToString([]byte(want)),
	} {
		got, err := decodeBase64String(enc)
		if err != nil || string(got) != want {
			t.Errorf("%q: got %q, %v", enc, got, err)
		}
	}
}

func TestParseHysteria2(t *testing.T) {
	n, err := parseLine("hysteria2://s3cret@h.example.com:8443?sni=h.example.com&insecure=1&obfs=salamander&obfs-password=op&alpn=h3#HY2")
	if err != nil {
		t.Fatal(err)
	}
	if n.Protocol != "hysteria2" || n.Password != "s3cret" || n.Port != "8443" || n.Name != "HY2" || n.SNI != "h.example.com" {
		t.Fatalf("unexpected %+v", n)
	}
	if n.Extra["skip-cert-verify"] != true || n.Extra["obfs"] != "salamander" || n.Extra["obfs-password"] != "op" {
		t.Fatalf("extra: %+v", n.Extra)
	}
	if n2, err := parseLine("hy2://pw@h.example.com#x"); err != nil || n2.Port != "443" {
		t.Fatalf("default port: %+v %v", n2, err)
	}
}

func TestParseTUIC(t *testing.T) {
	n, err := parseLine("tuic://11111111-2222:pw@t.example.com:443?congestion_control=bbr&udp_relay_mode=native&alpn=h3&sni=t.example.com#TUIC")
	if err != nil {
		t.Fatal(err)
	}
	if n.Protocol != "tuic" || n.UUID != "11111111-2222" || n.Password != "pw" || n.Extra["congestion-controller"] != "bbr" || n.Extra["udp-relay-mode"] != "native" {
		t.Fatalf("unexpected %+v", n)
	}
}

func TestClashYAMLKeepsExtrasForNativeProtocols(t *testing.T) {
	y := "proxies:\n  - {name: h, type: hysteria2, server: h.com, port: 443, password: pw, obfs: salamander, up: 50 Mbps}\n"
	nodes := parseClashYAML(y)
	if len(nodes) != 1 || nodes[0].Extra["obfs"] != "salamander" || nodes[0].Extra["up"] != "50 Mbps" {
		t.Fatalf("unexpected %+v", nodes)
	}
}
