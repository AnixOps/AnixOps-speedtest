package probe

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"

	"github.com/anixops/speedtest/internal/proxy"
)

// DefaultH3Target answers HTTP/3 and is the same URL the HTTP probe uses, so
// the H3 and HTTP numbers are directly comparable.
const DefaultH3Target = "https://www.gstatic.com/generate_204"

// H3Result is the HTTP/3 latency probe: each sample opens a fresh QUIC
// connection through the node (SOCKS5 UDP ASSOCIATE on the local kernel),
// then sends one GET over it.
type H3Result struct {
	Target string `json:"target"`
	// Ms is the median of handshake + request (the H3 counterpart of HTTPMs).
	Ms float64 `json:"ms"`
	// HandshakeMs is the median QUIC handshake (1-RTT to the target through
	// the node, plus whatever the node's own UDP carriage adds).
	HandshakeMs float64 `json:"handshake_ms"`
	Samples     int     `json:"samples"`
	JitterMs    float64 `json:"jitter_ms,omitempty"`
	LossPct     float64 `json:"loss_pct"`
	Status      int     `json:"status,omitempty"`
	// Unsupported is set when the local kernel refuses UDP ASSOCIATE, i.e. this
	// kernel cannot carry UDP at all; no samples were taken.
	Unsupported bool   `json:"unsupported,omitempty"`
	Error       string `json:"error,omitempty"`
}

// OK reports whether at least one sample succeeded.
func (r *H3Result) OK() bool { return r != nil && r.Ms > 0 }

type h3Sample struct {
	handshake time.Duration
	total     time.Duration
	status    int
}

// MeasureH3 takes n (>=1) HTTP/3 samples of target through proxyURL.
func MeasureH3(ctx context.Context, proxyURL, target string, timeout time.Duration, n int) (H3Result, []Evidence) {
	if target == "" {
		target = DefaultH3Target
	}
	if n < 1 {
		n = 1
	}
	res := H3Result{Target: target}
	var total, hs sampleSet
	var evidence []Evidence
	var lastErr error
	for i := 0; i < n && ctx.Err() == nil; i++ {
		s, err := h3Once(ctx, proxyURL, target, timeout)
		if errors.Is(err, proxy.ErrUDPUnsupported) {
			res.Unsupported = true
			res.Error = err.Error()
			return res, []Evidence{{Test: "latency_h3", URL: target, Method: "GET", RawError: err.Error()}}
		}
		ok := err == nil
		total.add(ms(s.total), ok)
		hs.add(ms(s.handshake), ok)
		if ok {
			res.Status = s.status
		} else {
			lastErr = err
		}
		if i == 0 {
			ev := Evidence{Test: "latency_h3", URL: target, Method: "GET", StatusCode: s.status, RawError: errStr(err)}
			if ok {
				ev.Timing = map[string]float64{"handshake": round1(ms(s.handshake)), "total": round1(ms(s.total))}
			}
			evidence = append(evidence, ev)
		}
	}
	res.Samples = total.total
	res.Ms = round1(total.median())
	res.HandshakeMs = round1(hs.median())
	res.JitterMs = total.jitter()
	res.LossPct = total.lossPct()
	if res.Ms <= 0 && lastErr != nil {
		res.Error = lastErr.Error()
	}
	return res, evidence
}

// h3RootCAs overrides the system roots in tests.
var h3RootCAs *x509.CertPool

func ms(d time.Duration) float64 { return float64(d) / float64(time.Millisecond) }

// h3Once opens a UDP association, dials QUIC (ALPN h3) to target's host and
// sends one GET. The association setup is local and not timed.
func h3Once(ctx context.Context, proxyURL, target string, timeout time.Duration) (h3Sample, error) {
	u, err := url.Parse(target)
	if err != nil {
		return h3Sample{}, err
	}
	if u.Scheme != "https" {
		return h3Sample{}, fmt.Errorf("h3 target must be https, got %q", target)
	}
	port := 443
	if p := u.Port(); p != "" {
		if port, err = strconv.Atoi(p); err != nil {
			return h3Sample{}, fmt.Errorf("h3 target port: %w", err)
		}
	}

	sctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	pc, err := proxy.ListenUDP(sctx, proxyURL, timeout)
	if err != nil {
		return h3Sample{}, err
	}
	defer pc.Close()

	tlsConf := &tls.Config{
		ServerName: u.Hostname(),
		NextProtos: []string{http3.NextProtoH3},
		MinVersion: tls.VersionTLS13,
		RootCAs:    h3RootCAs,
	}
	quicConf := &quic.Config{HandshakeIdleTimeout: timeout, MaxIdleTimeout: timeout}

	started := time.Now()
	conn, err := quic.Dial(sctx, pc, proxy.Addr{Host: u.Hostname(), Port: port}, tlsConf, quicConf)
	if err != nil {
		return h3Sample{}, fmt.Errorf("quic handshake: %w", err)
	}
	defer conn.CloseWithError(0, "")
	handshake := time.Since(started)

	cc := (&http3.Transport{}).NewClientConn(conn)
	req, err := http.NewRequestWithContext(sctx, http.MethodGet, target, nil)
	if err != nil {
		return h3Sample{}, err
	}
	req.Header.Set("Cache-Control", "no-cache")
	resp, err := cc.RoundTrip(req)
	if err != nil {
		return h3Sample{handshake: handshake}, fmt.Errorf("h3 request: %w", err)
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	resp.Body.Close()
	return h3Sample{handshake: handshake, total: time.Since(started), status: resp.StatusCode}, nil
}
