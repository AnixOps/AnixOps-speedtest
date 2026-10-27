package probe

import "testing"

func TestMedianJitterLoss(t *testing.T) {
	if got := median([]float64{5, 1, 3}); got != 3 {
		t.Errorf("odd median: %v", got)
	}
	if got := median([]float64{1, 2, 3, 10}); got != 2.5 {
		t.Errorf("even median: %v", got)
	}
	if median(nil) != 0 {
		t.Error("empty median must be 0")
	}
	if got := jitter([]float64{10, 20, 10}); got != 10 {
		t.Errorf("jitter: %v", got)
	}
	if jitter([]float64{7}) != 0 {
		t.Error("single-sample jitter must be 0")
	}
	var s sampleSet
	s.add(10, true)
	s.add(0, false)
	s.add(30, true)
	s.add(0, false)
	if s.lossPct() != 50 || s.median() != 20 {
		t.Errorf("loss=%v median=%v", s.lossPct(), s.median())
	}
}

func TestMbpsFromBytes(t *testing.T) {
	if got := mbpsFromBytes(1_250_000, 1e9); got != 10 { // 1.25 MB in 1s = 10 Mbps
		t.Errorf("got %v", got)
	}
	if mbpsFromBytes(0, 1e9) != 0 {
		t.Error("zero bytes")
	}
}

func TestNodeUp(t *testing.T) {
	cases := []struct {
		name string
		r    NodeResult
		want bool
	}{
		{"error", NodeResult{Error: "x"}, false},
		{"no latency test", NodeResult{}, true},
		{"both probes failed", NodeResult{Latency: &LatencyResult{}}, false},
		{"tcp only", NodeResult{Latency: &LatencyResult{TCPMs: 12}}, true},
		{"http only", NodeResult{Latency: &LatencyResult{HTTPMs: 12}}, true},
	}
	for _, c := range cases {
		if got := c.r.Up(); got != c.want {
			t.Errorf("%s: got %v", c.name, got)
		}
	}
}
