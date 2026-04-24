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
// accessID/accessSecret are optional Cloudflare Access Service Token credentials.
func PushMetrics(endpointURL, job string, results []probe.NodeResult, accessID, accessSecret string) error {
	var buf bytes.Buffer

	instance := hostname()

	fmt.Fprintf(&buf, "# TYPE speedtest_http_latency_ms gauge\n")
	fmt.Fprintf(&buf, "# TYPE speedtest_tcp_latency_ms gauge\n")
	fmt.Fprintf(&buf, "# TYPE speedtest_node_up gauge\n")
	fmt.Fprintf(&buf, "# TYPE speedtest_test_timestamp gauge\n")

	now := float64(time.Now().Unix())

	for _, r := range results {
		labels := fmt.Sprintf(`{instance="%s",node="%s",server="%s",type="%s"}`,
			instance,
			escapeLabel(r.Name),
			escapeLabel(fmt.Sprintf("%s:%d", r.Server, r.Port)),
			escapeLabel(r.Type),
		)

		buf.WriteString(fmt.Sprintf("speedtest_test_timestamp%s %.0f\n", labels, now))

		if r.Error != "" {
			buf.WriteString(fmt.Sprintf("speedtest_node_up%s 0\n", labels))
			continue
		}

		buf.WriteString(fmt.Sprintf("speedtest_node_up%s 1\n", labels))

		if r.Latency != nil {
			if r.Latency.HTTPMs > 0 {
				buf.WriteString(fmt.Sprintf("speedtest_http_latency_ms%s %s\n", labels, formatFloat(r.Latency.HTTPMs)))
			}
			if r.Latency.TCPMs > 0 {
				buf.WriteString(fmt.Sprintf("speedtest_tcp_latency_ms%s %s\n", labels, formatFloat(r.Latency.TCPMs)))
			}
		}
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
