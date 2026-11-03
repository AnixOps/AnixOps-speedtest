package probe

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/anixops/speedtest/internal/proxy"
)

// Throughput suite: several parallel connections download (then upload) for a
// fixed time while a small request is sent every ProbeEvery to measure the
// latency under load ("loaded latency", bufferbloat). This is the real-node
// counterpart of the anx lab WAN bench "speed" profile (8 connections, a probe
// every 0.5 s), so numbers from both are directly comparable.

// Default endpoints. The download URL gets the chunk size appended; the upload
// URL accepts a POST body of any size and discards it.
const (
	DefaultDownURL  = "https://speed.cloudflare.com/__down?bytes="
	DefaultUpURL    = "https://speed.cloudflare.com/__up"
	DefaultProbeURL = "https://www.gstatic.com/generate_204"
)

// ThroughputConfig controls the multi-connection throughput suite.
type ThroughputConfig struct {
	// Conns is the number of parallel connections per direction (default 8).
	Conns int
	// Duration is how long each direction runs (default 8s).
	Duration time.Duration
	// Upload enables the upload half (download always runs).
	Upload bool
	// MaxBytes stops a direction early once this many bytes moved (0 = no cap);
	// it bounds the traffic a scheduled run spends on a production node.
	MaxBytes int64
	// ChunkBytes is the size of each download request / upload body (default 25 MB).
	ChunkBytes int64
	// DownURL is a prefix the chunk size is appended to (default Cloudflare __down).
	DownURL string
	// UpURL receives POST bodies (default Cloudflare __up).
	UpURL string
	// ProbeURL is fetched on a fresh connection for idle and loaded latency.
	ProbeURL string
	// ProbeEvery is the loaded-latency probe interval (default 500ms).
	ProbeEvery time.Duration
	// IdleSamples is how many idle-latency probes run before the load (default 3).
	IdleSamples int
}

func (c ThroughputConfig) withDefaults() ThroughputConfig {
	if c.Conns <= 0 {
		c.Conns = 8
	}
	if c.Duration <= 0 {
		c.Duration = 8 * time.Second
	}
	if c.ChunkBytes <= 0 {
		c.ChunkBytes = 25_000_000
	}
	if strings.TrimSpace(c.DownURL) == "" {
		c.DownURL = DefaultDownURL
	}
	if strings.TrimSpace(c.UpURL) == "" {
		c.UpURL = DefaultUpURL
	}
	if strings.TrimSpace(c.ProbeURL) == "" {
		c.ProbeURL = DefaultProbeURL
	}
	if c.ProbeEvery <= 0 {
		c.ProbeEvery = 500 * time.Millisecond
	}
	if c.IdleSamples <= 0 {
		c.IdleSamples = 3
	}
	return c
}

// ThroughputResult is the outcome of the suite for one node.
type ThroughputResult struct {
	Conns int `json:"conns"`
	// IdleMs is the median probe latency before any load.
	IdleMs float64          `json:"idle_ms"`
	Down   *DirectionResult `json:"download,omitempty"`
	Up     *DirectionResult `json:"upload,omitempty"`
}

// DirectionResult is one direction's throughput and latency under that load.
type DirectionResult struct {
	Mbps     float64 `json:"mbps"`      // average over the whole run
	PeakMbps float64 `json:"peak_mbps"` // best 1-second window
	Bytes    int64   `json:"bytes"`
	Seconds  float64 `json:"seconds"`
	// PerSecondMbps is the throughput of each 1-second window, in order.
	PerSecondMbps []float64 `json:"per_second_mbps,omitempty"`
	// LoadedMs is the median probe latency while this direction ran;
	// BloatMs = LoadedMs - IdleMs (the queueing the load added).
	LoadedMs      float64 `json:"loaded_ms,omitempty"`
	LoadedP90Ms   float64 `json:"loaded_p90_ms,omitempty"`
	BloatMs       float64 `json:"bloat_ms,omitempty"`
	LoadedLossPct float64 `json:"loaded_loss_pct"`
	// Capped is true when MaxBytes ended the run before Duration.
	Capped bool   `json:"capped,omitempty"`
	Error  string `json:"error,omitempty"`
}

// MeasureThroughput runs the suite through proxyURL ("" = direct).
func MeasureThroughput(ctx context.Context, proxyURL string, timeout time.Duration, cfg ThroughputConfig) (ThroughputResult, error) {
	cfg = cfg.withDefaults()
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	probeClient, err := proxy.NewHTTPClient(proxyURL, timeout)
	if err != nil {
		return ThroughputResult{}, err
	}
	loadClient, err := proxy.NewHTTPClient(proxyURL, timeout)
	if err != nil {
		return ThroughputResult{}, err
	}
	// A transfer runs for the whole Duration; only the header wait is bounded.
	loadClient.Timeout = 0

	res := ThroughputResult{Conns: cfg.Conns}
	// One discarded probe first: the first request through a fresh kernel pays
	// the protocol's cold handshake, which would inflate the idle baseline and
	// make the loaded-minus-idle bloat come out negative.
	_, _ = probeOnce(ctx, probeClient, cfg.ProbeURL)
	var idle sampleSet
	for i := 0; i < cfg.IdleSamples; i++ {
		ms, ok := probeOnce(ctx, probeClient, cfg.ProbeURL)
		idle.add(ms, ok)
	}
	res.IdleMs = round1(idle.median())

	down := runDirection(ctx, loadClient, probeClient, cfg, false)
	down.finish(res.IdleMs)
	res.Down = &down
	if cfg.Upload && ctx.Err() == nil {
		up := runDirection(ctx, loadClient, probeClient, cfg, true)
		up.finish(res.IdleMs)
		res.Up = &up
	}
	return res, nil
}

func (d *DirectionResult) finish(idleMs float64) {
	if d.LoadedMs > 0 && idleMs > 0 {
		d.BloatMs = round1(d.LoadedMs - idleMs)
	}
}

// probeOnce fetches url on a fresh connection and returns its latency in ms.
func probeOnce(ctx context.Context, client *http.Client, url string) (float64, bool) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, false
	}
	req.Header.Set("Cache-Control", "no-cache")
	started := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return 0, false
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	resp.Body.Close()
	if resp.StatusCode >= 400 {
		return 0, false
	}
	return float64(time.Since(started)) / float64(time.Millisecond), true
}

func runDirection(parent context.Context, load, probeClient *http.Client, cfg ThroughputConfig, upload bool) DirectionResult {
	ctx, cancel := context.WithTimeout(parent, cfg.Duration)
	defer cancel()

	var moved atomic.Int64
	var capped atomic.Bool
	count := func(n int) {
		total := moved.Add(int64(n))
		if cfg.MaxBytes > 0 && total >= cfg.MaxBytes {
			capped.Store(true)
			cancel()
		}
	}

	started := time.Now()
	var wg sync.WaitGroup
	errs := make([]error, cfg.Conns)
	for i := 0; i < cfg.Conns; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			errs[i] = loadWorker(ctx, load, cfg, upload, count)
		}(i)
	}

	// Loaded-latency probes.
	var loaded sampleSet
	var probeMu sync.Mutex
	var probeWG sync.WaitGroup
	probeWG.Add(1)
	go func() {
		defer probeWG.Done()
		tick := time.NewTicker(cfg.ProbeEvery)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
				probeWG.Add(1)
				go func() {
					defer probeWG.Done()
					ms, ok := probeOnce(ctx, probeClient, cfg.ProbeURL)
					if ctx.Err() != nil && !ok {
						return // cut off by the end of the run, not a loss
					}
					probeMu.Lock()
					loaded.add(ms, ok)
					probeMu.Unlock()
				}()
			}
		}
	}()

	// Per-second throughput windows.
	var perSec []float64
	var secWG sync.WaitGroup
	secWG.Add(1)
	go func() {
		defer secWG.Done()
		tick := time.NewTicker(time.Second)
		defer tick.Stop()
		last := int64(0)
		for {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
				now := moved.Load()
				perSec = append(perSec, round1(mbpsFromBytes(now-last, time.Second)))
				last = now
			}
		}
	}()

	wg.Wait()
	elapsed := time.Since(started)
	cancel()
	probeWG.Wait()
	secWG.Wait()

	d := DirectionResult{
		Bytes:         moved.Load(),
		Seconds:       round1(elapsed.Seconds()),
		Mbps:          round1(mbpsFromBytes(moved.Load(), elapsed)),
		PerSecondMbps: perSec,
		LoadedMs:      round1(loaded.median()),
		LoadedP90Ms:   round1(percentile(loaded.ok, 90)),
		LoadedLossPct: loaded.lossPct(),
		Capped:        capped.Load(),
	}
	for _, v := range perSec {
		if v > d.PeakMbps {
			d.PeakMbps = v
		}
	}
	if d.PeakMbps == 0 {
		d.PeakMbps = d.Mbps // runs shorter than a second
	}
	if d.Bytes == 0 {
		d.Error = firstError(errs)
		if d.Error == "" {
			d.Error = "no data transferred"
		}
	}
	return d
}

// loadWorker keeps one connection busy until ctx ends.
func loadWorker(ctx context.Context, client *http.Client, cfg ThroughputConfig, upload bool, count func(int)) error {
	var lastErr error
	for ctx.Err() == nil {
		var err error
		if upload {
			err = uploadOnce(ctx, client, cfg, count)
		} else {
			err = downloadOnce(ctx, client, cfg, count)
		}
		if err != nil && ctx.Err() == nil {
			lastErr = err
			// Back off briefly so a refusing endpoint does not spin.
			select {
			case <-ctx.Done():
			case <-time.After(200 * time.Millisecond):
			}
		}
	}
	return lastErr
}

func downloadOnce(ctx context.Context, client *http.Client, cfg ThroughputConfig, count func(int)) error {
	url := cfg.DownURL
	if strings.HasSuffix(url, "=") {
		url += strconv.FormatInt(cfg.ChunkBytes, 10)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Cache-Control", "no-cache")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("download: HTTP %d", resp.StatusCode)
	}
	buf := make([]byte, 64<<10)
	for {
		n, err := resp.Body.Read(buf)
		if n > 0 {
			count(n)
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
	}
}

func uploadOnce(ctx context.Context, client *http.Client, cfg ThroughputConfig, count func(int)) error {
	body := &countingZeroReader{remaining: cfg.ChunkBytes, count: count}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.UpURL, body)
	if err != nil {
		return err
	}
	req.ContentLength = cfg.ChunkBytes
	req.Header.Set("Content-Type", "application/octet-stream")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("upload: HTTP %d", resp.StatusCode)
	}
	return nil
}

// countingZeroReader yields remaining zero bytes and reports each read.
type countingZeroReader struct {
	remaining int64
	count     func(int)
}

func (r *countingZeroReader) Read(p []byte) (int, error) {
	if r.remaining <= 0 {
		return 0, io.EOF
	}
	if int64(len(p)) > r.remaining {
		p = p[:r.remaining]
	}
	clear(p)
	r.remaining -= int64(len(p))
	r.count(len(p))
	return len(p), nil
}

func firstError(errs []error) string {
	for _, err := range errs {
		if err != nil {
			return err.Error()
		}
	}
	return ""
}

// percentile of v (nearest rank), 0 when empty.
func percentile(v []float64, p float64) float64 {
	if len(v) == 0 {
		return 0
	}
	c := append([]float64(nil), v...)
	sort.Float64s(c)
	rank := int(p/100*float64(len(c))+0.5) - 1
	if rank < 0 {
		rank = 0
	}
	if rank >= len(c) {
		rank = len(c) - 1
	}
	return c[rank]
}
