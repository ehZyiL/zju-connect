package desktop

import (
	"net"
	"sort"
	"strings"

	"github.com/mythologyli/zju-connect/client"
)

func resourceSnapshot(ips []client.IPResource, domains client.DomainResources, records map[string][]net.IP, cfg Config, remoteDNS string, tcpOnly bool) *ResourceSnapshot {
	s := &ResourceSnapshot{DNSServer: remoteDNS, Tunnel: "ipv4-l3"}
	if tcpOnly {
		s.Tunnel = "tcp"
	}
	for _, r := range ips {
		s.IPRules = append(s.IPRules, IPRule{Min: r.IPMin.String(), Max: r.IPMax.String(), PortMin: r.PortMin, PortMax: r.PortMax, Protocol: r.Protocol, AppID: r.AppID})
	}
	keys := make([]string, 0, len(domains))
	for name := range domains {
		keys = append(keys, name)
	}
	sort.Strings(keys)
	for _, name := range keys {
		for _, r := range domains[name] {
			s.DomainRules = append(s.DomainRules, DomainRule{Domain: name, PortMin: r.PortMin, PortMax: r.PortMax, Protocol: r.Protocol, AppID: r.AppID})
		}
	}
	keys = keys[:0]
	for name := range records {
		keys = append(keys, name)
	}
	sort.Strings(keys)
	for _, name := range keys {
		r := DNSRecord{Name: name}
		for _, ip := range records[name] {
			r.Addresses = append(r.Addresses, ip.String())
		}
		s.StaticDNS = append(s.StaticDNS, r)
	}
	seen := map[string]bool{}
	for _, name := range cfg.InternalDomains {
		name = strings.Trim(strings.ToLower(strings.TrimSpace(name)), ".")
		if name != "" && !seen[name] {
			seen[name] = true
			s.InternalDomains = append(s.InternalDomains, name)
		}
	}
	sort.Strings(s.InternalDomains)
	return s
}
