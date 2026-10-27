package probe

import (
	"context"
	"math"
	"sort"
	"time"
)

// sampleSet accumulates repeated measurements of one metric.
type sampleSet struct {
	ok    []float64
	total int
}

func (s *sampleSet) add(ms float64, success bool) {
	s.total++
	if success && ms > 0 {
		s.ok = append(s.ok, ms)
	}
}

// median of successful samples (0 when none succeeded).
func (s *sampleSet) median() float64 { return median(s.ok) }

// jitter is the mean absolute difference between consecutive successful
// samples (RFC 3550 style), 0 with fewer than two samples.
func (s *sampleSet) jitter() float64 { return jitter(s.ok) }

// lossPct is the share of failed attempts, in percent.
func (s *sampleSet) lossPct() float64 {
	if s.total == 0 {
		return 0
	}
	return round1(float64(s.total-len(s.ok)) / float64(s.total) * 100)
}

func median(v []float64) float64 {
	if len(v) == 0 {
		return 0
	}
	c := append([]float64(nil), v...)
	sort.Float64s(c)
	n := len(c)
	if n%2 == 1 {
		return c[n/2]
	}
	return (c[n/2-1] + c[n/2]) / 2
}

func jitter(v []float64) float64 {
	if len(v) < 2 {
		return 0
	}
	var sum float64
	for i := 1; i < len(v); i++ {
		sum += math.Abs(v[i] - v[i-1])
	}
	return round1(sum / float64(len(v)-1))
}

func round1(f float64) float64 { return math.Round(f*10) / 10 }

// measureLatencyRepeated runs measureLatency n times and aggregates. With n<=1 it
// behaves exactly like a single measurement and reports no aggregate fields.
func measureLatencyRepeated(ctx context.Context, proxyURL string, timeout time.Duration, n int) (LatencyResult, []Evidence) {
	if n <= 1 {
		return measureLatency(ctx, proxyURL, timeout)
	}
	var httpS, tcpS sampleSet
	var evidence []Evidence
	for i := 0; i < n && ctx.Err() == nil; i++ {
		r, ev := measureLatency(ctx, proxyURL, timeout)
		httpS.add(r.HTTPMs, r.HTTPMs > 0)
		tcpS.add(r.TCPMs, r.TCPMs > 0)
		// Keep evidence of the first attempt only; repeats would bloat reports.
		if i == 0 {
			evidence = ev
		}
	}
	return LatencyResult{
		HTTPMs:       round1(httpS.median()),
		TCPMs:        round1(tcpS.median()),
		Samples:      httpS.total,
		HTTPJitterMs: httpS.jitter(),
		HTTPLossPct:  httpS.lossPct(),
		TCPLossPct:   tcpS.lossPct(),
	}, evidence
}
