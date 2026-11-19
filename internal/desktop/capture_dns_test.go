package desktop

import (
	"github.com/miekg/dns"
	"github.com/mythologyli/zju-connect/client"
	"net"
	"testing"
)

func TestCaptureDNSDoesNotGrantDomainPermissionsToSharedIP(t *testing.T) {
	q := new(dns.Msg).SetQuestion("app.corp.test.", dns.TypeA)
	answer := new(dns.Msg).SetReply(q)
	answer.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 30}, A: net.ParseIP("10.1.2.3")}}
	if got := captureDNSAnswer(q, answer, nil, nil); got.Rcode != dns.RcodeServerFailure {
		t.Fatal("domain-only answer granted IP routing authority")
	}
	rules := []client.IPResource{{IPMin: net.ParseIP("10.1.2.0"), IPMax: net.ParseIP("10.1.2.255"), PortMin: 443, PortMax: 443, Protocol: "tcp"}}
	got := captureDNSAnswer(q, answer, rules, nil)
	if got.Rcode != dns.RcodeSuccess || len(got.Answer) != 1 || got.Answer[0].Header().Ttl != 30 {
		t.Fatal("IP-authorized answer lost")
	}
	if rules[0].PortMin != 443 || rules[0].PortMax != 443 {
		t.Fatal("DNS broadened gateway port authority")
	}
	answer.Answer[0].(*dns.A).A = net.ParseIP("10.9.9.9")
	if got := captureDNSAnswer(q, answer, rules, nil); got.Rcode != dns.RcodeServerFailure {
		t.Fatal("unlisted address accepted")
	}
	q.SetQuestion("app.corp.test.", dns.TypeAAAA)
	answer = new(dns.Msg).SetReply(q)
	answer.Answer = []dns.RR{&dns.AAAA{Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 30}, AAAA: net.ParseIP("fd00::1")}}
	if got := captureDNSAnswer(q, answer, rules, nil); got.Rcode != dns.RcodeSuccess || len(got.Answer) != 0 {
		t.Fatal("internal IPv6 escaped unsupported capture")
	}
}

func TestCaptureDNSFiltersAdditionalHintsAndRejectsAliasEscape(t *testing.T) {
	q := new(dns.Msg).SetQuestion("app.corp.test.", dns.TypeA)
	m := new(dns.Msg).SetReply(q)
	m.AuthenticatedData = true
	a, _ := dns.NewRR("app.corp.test. 31 IN A 10.1.2.3")
	alias, _ := dns.NewRR("app.corp.test. 29 IN CNAME target.corp.test.")
	AAAA, _ := dns.NewRR("target.corp.test. 31 IN AAAA fd00::1")
	m.Answer = []dns.RR{alias, a}
	m.Extra = []dns.RR{AAAA}
	rules := []client.IPResource{{IPMin: net.ParseIP("10.1.2.3"), IPMax: net.ParseIP("10.1.2.3"), PortMin: 443, PortMax: 443, Protocol: "tcp"}}
	internal := func(name string) bool { return name == "target.corp.test." }
	got := captureDNSAnswer(q, m, rules, internal)
	if got.Rcode != dns.RcodeSuccess || len(got.Answer) != 2 || got.Answer[1].Header().Ttl != 31 || len(got.Extra) != 0 || got.AuthenticatedData {
		t.Fatalf("capture filtering failed: %v", got)
	}
	if len(m.Extra) != 1 || !m.AuthenticatedData {
		t.Fatal("capture mutated original diagnostic answer")
	}
	alias.(*dns.CNAME).Target = "outside.example."
	if got := captureDNSAnswer(q, m, rules, internal); got.Rcode != dns.RcodeServerFailure {
		t.Fatal("CNAME escaped internal DNS")
	}
}
