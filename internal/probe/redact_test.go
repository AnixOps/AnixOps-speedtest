package probe

import (
	"strings"
	"testing"

	"github.com/anixops/speedtest/internal/checker"
	"github.com/anixops/speedtest/internal/topo"
)

func TestMaskHost(t *testing.T) {
	cases := map[string]string{
		"203.0.113.7":      "203.0.*.*",
		"2001:db8::1":      "2001:db8::*",
		"hk01.example.com": "h***.***.com",
		"localhost":        "l***",
		"":                 "",
	}
	for in, want := range cases {
		if got := MaskHost(in); got != want {
			t.Errorf("%q: got %q want %q", in, got, want)
		}
	}
}

func TestRedactHidesAddressesAndDoesNotMutateInput(t *testing.T) {
	in := []NodeResult{{
		Name: "n", Server: "198.51.100.9", Port: 443,
		Error:    "dial tcp 198.51.100.9:443: timeout",
		IPRisk:   &checker.IPRiskResult{IP: "198.51.100.9"},
		Topology: &topo.TopologyResult{EntryIP: "192.0.2.55", ExitIP: "198.51.100.9"},
		SSH:      &checker.SSHResult{Detail: "to 198.51.100.9 failed"},
		Evidence: []Evidence{{Body: "198.51.100.9"}},
	}}
	out := Redact(in)
	if in[0].Server != "198.51.100.9" || in[0].Evidence == nil || in[0].Topology.EntryIP != "192.0.2.55" {
		t.Fatal("input was mutated")
	}
	r := out[0]
	if r.Evidence != nil {
		t.Error("evidence must be dropped")
	}
	for _, s := range []string{r.Server, r.Error, r.IPRisk.IP, r.Topology.EntryIP, r.Topology.ExitIP, r.SSH.Detail} {
		if strings.Contains(s, "198.51.100.9") || strings.Contains(s, "192.0.2.55") {
			t.Errorf("leaked address in %q", s)
		}
	}
}
