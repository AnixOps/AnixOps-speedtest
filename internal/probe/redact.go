package probe

import (
	"net"
	"strings"
)

// MaskHost hides most of a server address while keeping it recognisable:
// 203.0.113.7 -> 203.0.*.*, 2001:db8::1 -> 2001:db8::*, hk01.example.com -> h***.***.com.
func MaskHost(host string) string {
	host = strings.TrimSpace(host)
	if host == "" {
		return ""
	}
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			parts := strings.Split(v4.String(), ".")
			return parts[0] + "." + parts[1] + ".*.*"
		}
		parts := strings.Split(ip.String(), ":")
		if len(parts) < 2 {
			return "*"
		}
		return parts[0] + ":" + parts[1] + "::*"
	}
	labels := strings.Split(host, ".")
	if len(labels) == 1 {
		return string(labels[0][0]) + "***"
	}
	for i := range labels[:len(labels)-1] {
		if i == 0 {
			labels[i] = string(labels[i][0]) + "***"
		} else {
			labels[i] = "***"
		}
	}
	return strings.Join(labels, ".")
}

// Redact returns a copy of results that is safe to share: server addresses and
// every discovered IP (including the tester's own entry IP) are masked, raw
// request/response evidence is dropped, and addresses embedded in error text are
// replaced. Redact BEFORE signing so the certificate covers what is published.
func Redact(results []NodeResult) []NodeResult {
	out := make([]NodeResult, len(results))
	for i, r := range results {
		server := r.Server
		masked := MaskHost(server)
		scrub := func(s string) string {
			if server != "" {
				s = strings.ReplaceAll(s, server, masked)
			}
			return s
		}

		r.Server = masked
		r.Error = scrub(r.Error)
		r.Evidence = nil

		if r.IPRisk != nil {
			c := *r.IPRisk
			c.IP = MaskHost(c.IP)
			r.IPRisk = &c
		}
		if r.DNS != nil {
			c := *r.DNS
			c.IP = MaskHost(c.IP)
			r.DNS = &c
		}
		if r.Topology != nil {
			c := *r.Topology
			c.EntryIP = MaskHost(c.EntryIP)
			c.ExitIP = MaskHost(c.ExitIP)
			r.Topology = &c
		}
		if r.SSH != nil {
			c := *r.SSH
			c.Detail = scrub(c.Detail)
			r.SSH = &c
		}
		out[i] = r
	}
	return out
}
