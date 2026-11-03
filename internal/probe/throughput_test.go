package probe

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// speedServer serves /down?bytes=N, /up (POST sink) and /204, optionally
// slowing /204 while a transfer is in flight to simulate bufferbloat.
func speedServer(t *testing.T, loadedDelay time.Duration) *httptest.Server {
	t.Helper()
	var active atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("/down", func(w http.ResponseWriter, r *http.Request) {
		active.Add(1)
		defer active.Add(-1)
		n, _ := strconv.ParseInt(r.URL.Query().Get("bytes"), 10, 64)
		w.Header().Set("Content-Length", strconv.FormatInt(n, 10))
		buf := make([]byte, 32<<10)
		for n > 0 {
			k := int64(len(buf))
			if n < k {
				k = n
			}
			if _, err := w.Write(buf[:k]); err != nil {
				return
			}
			n -= k
			time.Sleep(2 * time.Millisecond) // ~16 MB/s per connection
		}
	})
	mux.HandleFunc("/up", func(w http.ResponseWriter, r *http.Request) {
		active.Add(1)
		defer active.Add(-1)
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/204", func(w http.ResponseWriter, r *http.Request) {
		if active.Load() > 0 {
			time.Sleep(loadedDelay)
		}
		w.WriteHeader(http.StatusNoContent)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func TestMeasureThroughputDownUpAndLoadedLatency(t *testing.T) {
	srv := speedServer(t, 40*time.Millisecond)
	res, err := MeasureThroughput(context.Background(), "", 5*time.Second, ThroughputConfig{
		Conns:      4,
		Duration:   1500 * time.Millisecond,
		Upload:     true,
		ChunkBytes: 4 << 20,
		DownURL:    srv.URL + "/down?bytes=",
		UpURL:      srv.URL + "/up",
		ProbeURL:   srv.URL + "/204",
		ProbeEvery: 100 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Conns != 4 || res.IdleMs <= 0 {
		t.Fatalf("conns/idle: %+v", res)
	}
	for name, d := range map[string]*DirectionResult{"down": res.Down, "up": res.Up} {
		if d == nil {
			t.Fatalf("%s missing", name)
		}
		if d.Bytes <= 0 || d.Mbps <= 0 || d.PeakMbps < d.Mbps*0.5 {
			t.Errorf("%s throughput: %+v", name, d)
		}
		if d.Error != "" {
			t.Errorf("%s error: %s", name, d.Error)
		}
		if d.LoadedMs < 40 {
			t.Errorf("%s loaded latency %.1f ms, want >= 40 (server delays probes under load)", name, d.LoadedMs)
		}
		if d.BloatMs < 30 {
			t.Errorf("%s bloat %.1f ms, want >= 30", name, d.BloatMs)
		}
		if len(d.PerSecondMbps) == 0 {
			t.Errorf("%s has no per-second samples", name)
		}
	}
}

func TestMeasureThroughputByteCap(t *testing.T) {
	srv := speedServer(t, 0)
	started := time.Now()
	res, err := MeasureThroughput(context.Background(), "", 5*time.Second, ThroughputConfig{
		Conns:      2,
		Duration:   10 * time.Second,
		MaxBytes:   2 << 20,
		ChunkBytes: 64 << 20,
		DownURL:    srv.URL + "/down?bytes=",
		ProbeURL:   srv.URL + "/204",
	})
	if err != nil {
		t.Fatal(err)
	}
	if time.Since(started) > 5*time.Second {
		t.Fatalf("cap did not stop the run early")
	}
	if res.Down == nil || !res.Down.Capped || res.Down.Bytes < 2<<20 {
		t.Fatalf("down: %+v", res.Down)
	}
	if res.Up != nil {
		t.Fatalf("upload ran without Upload")
	}
}

func TestMeasureThroughputDeadEndpoint(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusForbidden)
	}))
	defer srv.Close()
	res, err := MeasureThroughput(context.Background(), "", 2*time.Second, ThroughputConfig{
		Conns:      2,
		Duration:   500 * time.Millisecond,
		ProbeEvery: 100 * time.Millisecond,
		DownURL:    srv.URL + "/down?bytes=",
		ProbeURL:   srv.URL + "/204",
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Down == nil || res.Down.Bytes != 0 || !strings.Contains(res.Down.Error, "403") {
		t.Fatalf("down: %+v", res.Down)
	}
	if res.Down.LoadedLossPct != 100 {
		t.Fatalf("probes against a 403 should all count as loss, got %.1f", res.Down.LoadedLossPct)
	}
}

func TestPercentile(t *testing.T) {
	v := []float64{5, 1, 4, 2, 3, 10, 9, 8, 7, 6}
	if got := percentile(v, 90); got != 9 {
		t.Fatalf("p90 = %v", got)
	}
	if got := percentile(nil, 90); got != 0 {
		t.Fatalf("empty p90 = %v", got)
	}
}
