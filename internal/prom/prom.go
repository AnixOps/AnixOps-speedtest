package prom

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/anixops/speedtest/internal/probe"
)

// PushMetrics sends node latency metrics to a Prometheus Pushgateway or
// any endpoint that accepts OpenMetrics text format via POST.
// endpointURL is like "https://prometheus.anixops.com" —
// "/metrics/job/{job}" is appended automatically.
// kernel labels every series with the proxy kernel that ran the test.
// accessID/accessSecret are optional Cloudflare Access Service Token credentials.
func PushMetrics(endpointURL, job, kernel string, results []probe.NodeResult, accessID, accessSecret string) error {
	var buf bytes.Buffer

	instance := hostname()

	fmt.Fprintf(&buf, "# TYPE speedtest_http_latency_ms gauge\n")
	fmt.Fprintf(&buf, "# TYPE speedtest_tcp_latency_ms gauge\n")
	fmt.Fprintf(&buf, "# TYPE speedtest_cold_ms gauge\n")
	fmt.Fprintf(&buf, "# TYPE speedtest_tcp_warm_ms gauge\n")
	fmt.Fprintf(&buf, "# TYPE speedtest_http_jitter_ms gauge\n")
	fmt.Fprintf(&buf, "# TYPE speedtest_http_loss_pct gauge\n")
	fmt.Fprintf(&buf, "# TYPE speedtest_node_up gauge\n")
	for _, m := range throughputMetrics {
		fmt.Fprintf(&buf, "# TYPE %s gauge\n", m)
	}
	fmt.Fprintf(&buf, "# TYPE speedtest_test_timestamp gauge\n")

	now := float64(time.Now().Unix())

	for _, r := range results {
		labels := fmt.Sprintf(`{instance="%s",node="%s",server="%s",type="%s",kernel="%s"}`,
			instance,
			escapeLabel(r.Name),
			escapeLabel(fmt.Sprintf("%s:%d", r.Server, r.Port)),
			escapeLabel(r.Type),
			escapeLabel(kernel),
		)

		buf.WriteString(fmt.Sprintf("speedtest_test_timestamp%s %.0f\n", labels, now))

		if !r.Up() {
			buf.WriteString(fmt.Sprintf("speedtest_node_up%s 0\n", labels))
			continue
		}

		buf.WriteString(fmt.Sprintf("speedtest_node_up%s 1\n", labels))

		if r.Latency != nil {
			if r.Latency.HTTPMs > 0 {
				buf.WriteString(fmt.Sprintf("speedtest_http_latency_ms%s %s\n", labels, formatFloat(r.Latency.HTTPMs)))
			}
			if r.Latency.Samples > 1 {
				buf.WriteString(fmt.Sprintf("speedtest_http_jitter_ms%s %s\n", labels, formatFloat(r.Latency.HTTPJitterMs)))
				buf.WriteString(fmt.Sprintf("speedtest_http_loss_pct%s %s\n", labels, formatFloat(r.Latency.HTTPLossPct)))
			}
			if r.Latency.TCPMs > 0 {
				buf.WriteString(fmt.Sprintf("speedtest_tcp_latency_ms%s %s\n", labels, formatFloat(r.Latency.TCPMs)))
			}
			// First connection through a fresh kernel vs later ones on a kept session.
			if r.Latency.ColdMs > 0 {
				buf.WriteString(fmt.Sprintf("speedtest_cold_ms%s %s\n", labels, formatFloat(r.Latency.ColdMs)))
			}
			if r.Latency.WarmTCPMs > 0 {
				buf.WriteString(fmt.Sprintf("speedtest_tcp_warm_ms%s %s\n", labels, formatFloat(r.Latency.WarmTCPMs)))
			}
		}
		writeThroughput(&buf, labels, r.Throughput)
	}

	url := buildPushURL(endpointURL, job)
	req, err := http.NewRequest(http.MethodPost, url, &buf)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "text/plain; version=0.0.4")
	if accessID != "" && accessSecret != "" {
		req.Header.Set("CF-Access-Client-Id", accessID)
		req.Header.Set("CF-Access-Client-Secret", accessSecret)
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("push to %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("push returned %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// buildPushURL ensures the URL ends with /metrics/job/{job} (Pushgateway convention).
func buildPushURL(endpointURL, job string) string {
	endpointURL = strings.TrimRight(endpointURL, "/")
	if strings.HasSuffix(endpointURL, "/metrics/job/"+job) {
		return endpointURL
	}
	if strings.HasSuffix(endpointURL, "/metrics") {
		return endpointURL + "/job/" + job
	}
	return endpointURL + "/metrics/job/" + job
}

func formatFloat(f float64) string {
	return strconv.FormatFloat(f, 'f', 2, 64)
}

func escapeLabel(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	s = strings.ReplaceAll(s, "\n", `\n`)
	return s
}

func hostname() string {
	h, _ := os.Hostname()
	if h == "" {
		h = "unknown"
	}
	return h
}

var throughputMetrics = []string{
	"speedtest_idle_ms",
	"speedtest_down_mbps", "speedtest_down_peak_mbps", "speedtest_down_loaded_ms", "speedtest_down_bloat_ms", "speedtest_down_loaded_loss_pct",
	"speedtest_up_mbps", "speedtest_up_peak_mbps", "speedtest_up_loaded_ms", "speedtest_up_bloat_ms", "speedtest_up_loaded_loss_pct",
}

// writeThroughput emits the multi-connection suite; a direction that moved no
// data reports 0 Mbit/s and no latency series.
func writeThroughput(buf *bytes.Buffer, labels string, t *probe.ThroughputResult) {
	if t == nil {
		return
	}
	if t.IdleMs > 0 {
		fmt.Fprintf(buf, "speedtest_idle_ms%s %s\n", labels, formatFloat(t.IdleMs))
	}
	for _, d := range []struct {
		name string
		r    *probe.DirectionResult
	}{{"down", t.Down}, {"up", t.Up}} {
		if d.r == nil {
			continue
		}
		fmt.Fprintf(buf, "speedtest_%s_mbps%s %s\n", d.name, labels, formatFloat(d.r.Mbps))
		fmt.Fprintf(buf, "speedtest_%s_peak_mbps%s %s\n", d.name, labels, formatFloat(d.r.PeakMbps))
		if d.r.LoadedMs > 0 {
			fmt.Fprintf(buf, "speedtest_%s_loaded_ms%s %s\n", d.name, labels, formatFloat(d.r.LoadedMs))
			fmt.Fprintf(buf, "speedtest_%s_bloat_ms%s %s\n", d.name, labels, formatFloat(d.r.BloatMs))
		}
		fmt.Fprintf(buf, "speedtest_%s_loaded_loss_pct%s %s\n", d.name, labels, formatFloat(d.r.LoadedLossPct))
	}
}
