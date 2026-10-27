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
		{Name: `HK "01"`, Type: "vmess", Server: "hk.example.com", Port: 443, Latency: &probe.LatencyResult{HTTPMs: 12.5, TCPMs: 3}},
		{Name: "down", Type: "ss", Server: "x", Port: 1, Error: "timeout"},
	}
	if err := PushMetrics(srv.URL, "speedtest", results, "cid", "secret"); err != nil {
		t.Fatal(err)
	}
	if id != "cid" {
		t.Errorf("access header missing")
	}
	for _, want := range []string{`node="HK \"01\""`, "speedtest_http_latency_ms{", " 12.50\n", `speedtest_node_up{instance=`, `node="down"`} {
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
	if err := PushMetrics(srv.URL, "j", nil, "", ""); err == nil {
		t.Fatal("expected error on 500")
	}
}
