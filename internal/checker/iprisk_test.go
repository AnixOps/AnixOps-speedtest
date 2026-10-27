package checker

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestScoreIPRisk(t *testing.T) {
	cases := []struct {
		f     ipFlags
		level string
		ptype string
	}{
		{ipFlags{}, "low", ""},
		{ipFlags{Datacenter: true}, "high", "datacenter"},
		{ipFlags{Proxy: true}, "high", "proxy"},
		{ipFlags{VPN: true, Datacenter: true}, "high", "vpn"},
		{ipFlags{Tor: true, VPN: true}, "high", "tor"},
		{ipFlags{Abuser: true}, "medium", ""},
	}
	for _, c := range cases {
		_, level, ptype := scoreIPRisk(c.f)
		if level != c.level || ptype != c.ptype {
			t.Errorf("%+v: got %s/%s want %s/%s", c.f, level, ptype, c.level, c.ptype)
		}
	}
}

func TestParseIPAPIIs(t *testing.T) {
	body := []byte(`{"ip":"1.2.3.4","is_datacenter":true,"is_vpn":false,"company":{"name":"Acme","type":"hosting"},"location":{"country":"Japan"}}`)
	ip, f, ok := parseIPAPIIs(body)
	if !ok || ip != "1.2.3.4" || !f.Datacenter || f.Country != "Japan" || f.ISP != "Acme" {
		t.Fatalf("got %v %+v %v", ip, f, ok)
	}
	if _, _, ok := parseIPAPIIs([]byte(`{"error":"x"}`)); ok {
		t.Fatal("must reject payload without ip")
	}
}

func TestParseIPAPICom(t *testing.T) {
	ip, f, ok := parseIPAPICom([]byte(`{"status":"success","country":"US","isp":"X","proxy":true,"hosting":false,"query":"9.9.9.9"}`))
	if !ok || ip != "9.9.9.9" || !f.Proxy {
		t.Fatalf("got %v %+v %v", ip, f, ok)
	}
	if _, _, ok := parseIPAPICom([]byte(`{"status":"fail"}`)); ok {
		t.Fatal("must reject failed status")
	}
}

func TestProviderLookup(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"ip":"5.6.7.8","is_proxy":true}`))
	}))
	defer srv.Close()
	p := riskProvider{name: "t", url: func(string) string { return srv.URL }, parse: parseIPAPIIs}
	ip, f, ev, ok := p.lookup(context.Background(), srv.Client(), "")
	if !ok || ip != "5.6.7.8" || !f.Proxy || ev.StatusCode != 200 {
		t.Fatalf("got %v %+v %+v %v", ip, f, ev, ok)
	}
}

func TestRateGateSpacesCalls(t *testing.T) {
	g := &rateGate{interval: 40 * time.Millisecond}
	start := time.Now()
	for i := 0; i < 3; i++ {
		if err := g.wait(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if d := time.Since(start); d < 70*time.Millisecond {
		t.Fatalf("calls not spaced: %v", d)
	}
}

func TestRiskCache(t *testing.T) {
	cachePut("10.0.0.1", IPRiskResult{IP: "10.0.0.1", RiskLevel: "low"})
	if r, ok := cacheGet("10.0.0.1"); !ok || r.RiskLevel != "low" {
		t.Fatal("expected hit")
	}
	if _, ok := cacheGet("10.0.0.2"); ok {
		t.Fatal("unexpected hit")
	}
}

func TestParseProxyCheck(t *testing.T) {
	body := []byte(`{"status":"ok","5.196.77.102":{"provider":"OVH SAS","isocode":"FR","proxy":"yes","type":"VPN"}}`)
	ip, f, ok := parseProxyCheck(body)
	if !ok || ip != "5.196.77.102" || !f.VPN || f.Country != "FR" || f.ISP != "OVH SAS" {
		t.Fatalf("got %v %+v %v", ip, f, ok)
	}
	_, f, ok = parseProxyCheck([]byte(`{"status":"ok","1.1.1.1":{"proxy":"no"}}`))
	if !ok || f.VPN || f.Proxy {
		t.Fatalf("clean ip flagged: %+v", f)
	}
	if _, _, ok := parseProxyCheck([]byte(`{"status":"error","message":"x"}`)); ok {
		t.Fatal("error status must be rejected")
	}
}

func TestParseIPAPIIsFreeTierStringCompany(t *testing.T) {
	ip, f, ok := parseIPAPIIs([]byte(`{"ip":"1.2.3.4","company":"OVH SAS","country":"France"}`))
	if !ok || ip != "1.2.3.4" || f.ISP != "OVH SAS" || f.Country != "France" {
		t.Fatalf("got %v %+v %v", ip, f, ok)
	}
}
