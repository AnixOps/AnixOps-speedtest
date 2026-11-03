package prom

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/anixops/speedtest/internal/probe"
)

func TestBuildPushURL(t *testing.T) {
	cases := map[string]string{
		"http://h:9091":                  "http://h:9091/metrics/job/j",
		"http://h:9091/":                 "http://h:9091/metrics/job/j",
		"http://h:9091/metrics":          "http://h:9091/metrics/job/j",
		"http://h:9091/metrics/job/j":    "http://h:9091/metrics/job/j",
		"http://h:9091/metrics/job/j///": "http://h:9091/metrics/job/j",
	}
	for in, want := range cases {
		if got := buildPushURL(in, "j"); got != want {
			t.Errorf("%s: got %s want %s", in, got, want)
		}
	}
}

func TestEscapeLabel(t *testing.T) {
	if got := escapeLabel("a\"b\\c\nd"); got != `a\"b\\c\nd` {
		t.Fatalf("got %q", got)
	}
}

func TestPushMetrics(t *testing.T) {
	var body, id string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		body, id = string(b), r.Header.Get("CF-Access-Client-Id")
		if r.Method != http.MethodPost || r.URL.Path != "/metrics/job/speedtest" {
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer srv.Close()

	results := []probe.NodeResult{
		{Name: `HK "01"`, Type: "vmess", Server: "hk.example.com", Port: 443, Latency: &probe.LatencyResult{HTTPMs: 12.5, TCPMs: 3, Samples: 3, ColdMs: 40, WarmTCPMs: 3}},
		{Name: "down", Type: "ss", Server: "x", Port: 1, Error: "timeout"},
	}
	if err := PushMetrics(srv.URL, "speedtest", "mihomo", results, "cid", "secret"); err != nil {
		t.Fatal(err)
	}
	if id != "cid" {
		t.Errorf("access header missing")
	}
	for _, want := range []string{`node="HK \"01\""`, "speedtest_http_latency_ms{", " 12.50\n", `speedtest_node_up{instance=`, `node="down"`, `kernel="mihomo"`, "speedtest_cold_ms{", "speedtest_tcp_warm_ms{"} {
		if !strings.Contains(body, want) {
			t.Errorf("body missing %q:\n%s", want, body)
		}
	}
	if strings.Count(body, "speedtest_node_up") < 3 { // TYPE line + 2 samples
		t.Errorf("expected node_up for both nodes:\n%s", body)
	}
}

func TestPushMetricsServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Error(w, "boom", 500) }))
	defer srv.Close()
	if err := PushMetrics(srv.URL, "j", "mihomo", nil, "", ""); err == nil {
		t.Fatal("expected error on 500")
	}
}

func TestPushMetricsThroughput(t *testing.T) {
	var body string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		body = string(b)
	}))
	defer srv.Close()

	results := []probe.NodeResult{{
		Name: "DE", Type: "anx", Server: "de", Port: 443,
		Latency: &probe.LatencyResult{HTTPMs: 30, TCPMs: 20},
		Throughput: &probe.ThroughputResult{
			Conns: 8, IdleMs: 30,
			Down: &probe.DirectionResult{Mbps: 200, PeakMbps: 250, Bytes: 1, LoadedMs: 60, BloatMs: 30},
			Up:   &probe.DirectionResult{Mbps: 0, Error: "no data transferred", LoadedLossPct: 100},
		},
	}}
	if err := PushMetrics(srv.URL, "j", "anx", results, "", ""); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"# TYPE speedtest_down_mbps gauge", "speedtest_idle_ms{", "speedtest_down_mbps{", " 200.00\n",
		"speedtest_down_peak_mbps{", "speedtest_down_loaded_ms{", "speedtest_down_bloat_ms{",
		"speedtest_up_mbps{", "speedtest_up_loaded_loss_pct{",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("body missing %q:\n%s", want, body)
		}
	}
	if strings.Contains(body, "speedtest_up_loaded_ms{") {
		t.Errorf("failed upload should not report a loaded latency:\n%s", body)
	}
}
