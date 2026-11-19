package desktop

import (
	"bytes"
	"net"

	"github.com/miekg/dns"
	"github.com/mythologyli/zju-connect/client"
)

// Raw diagnostic queries are unchanged. A transparent application only gives
// the proxy an IP, so DNS may not turn domain-only authority into IP authority.
// Until domain identity can survive that hop, those addresses fail explicitly.
func captureDNSAnswer(q, m *dns.Msg, rules []client.IPResource, internal func(string) bool) *dns.Msg {
	if m.Rcode != dns.RcodeSuccess || len(q.Question) != 1 {
		return m
	}
	switch q.Question[0].Qtype {
	case dns.TypeANY:
		return new(dns.Msg).SetRcode(q, dns.RcodeRefused)
	case dns.TypeAAAA, dns.TypeHTTPS, dns.TypeSVCB:
		// IPv6 capture and address hints are not supported yet. An empty answer
		// lets clients use A/TCP instead of sending internal IPv6 outside the VPN.
		r := new(dns.Msg).SetReply(q)
		r.RecursionAvailable = true
		return r
	}
	allowed := func(ip net.IP) bool {
		ip = ip.To4()
		if ip == nil || ip.IsLoopback() || ip.IsUnspecified() || ip.IsMulticast() {
			return false
		}
		for _, rule := range rules {
			lo, hi := rule.IPMin.To4(), rule.IPMax.To4()
			if lo != nil && hi != nil && (rule.Protocol == "tcp" || rule.Protocol == "all") && rule.PortMin > 0 && rule.PortMax >= rule.PortMin && rule.PortMax <= 65535 && bytes.Compare(ip, lo) >= 0 && bytes.Compare(ip, hi) <= 0 {
				return true
			}
		}
		return false
	}
	// Never let unsupported IPv6 or HTTPS address hints escape in additional
	// records either. Preserve the original packet for the diagnostic path.
	m = m.Copy()
	changed := false
	for _, section := range []*[]dns.RR{&m.Answer, &m.Ns, &m.Extra} {
		kept := (*section)[:0]
		for _, rr := range *section {
			var target string
			switch record := rr.(type) {
			case *dns.A:
				if !allowed(record.A) {
					return new(dns.Msg).SetRcode(q, dns.RcodeServerFailure)
				}
			case *dns.AAAA, *dns.HTTPS, *dns.SVCB, *dns.RRSIG:
				changed = true
				continue
			case *dns.CNAME:
				target = record.Target
			case *dns.DNAME:
				target = record.Target
			case *dns.MX:
				target = record.Mx
			case *dns.SRV:
				target = record.Target
			}
			// Chasing an internal alias through the public resolver would lose
			// the session's DNS policy, including when glue is already present.
			if target != "" && target != "." && (internal == nil || !internal(target)) {
				return new(dns.Msg).SetRcode(q, dns.RcodeServerFailure)
			}
			kept = append(kept, rr)
		}
		*section = kept
	}
	if changed {
		m.AuthenticatedData = false
	}
	return m
}
