package resolve

import (
	"context"
	"github.com/miekg/dns"
	"testing"
)

func TestCNAMEFollowupStaysOnSelectedGatewayAndRejectsLoops(t *testing.T) {
	for _, loop := range []bool{false, true} {
		r := NewResolver(nil, "10.0.0.53", "", 60, nil, nil, true)
		r.EnableSplitDNS([]string{"corp.test"})
		calls := 0
		r.wireExchange = func(_ context.Context, network string, q *dns.Msg) (*dns.Msg, error) {
			calls++
			m := new(dns.Msg).SetReply(q)
			line := "app.corp.test. 30 IN CNAME canonical.external.test."
			if q.Question[0].Name == "canonical.external.test." {
				line = "canonical.external.test. 20 IN A 10.0.0.8"
				if loop {
					line = "canonical.external.test. 20 IN CNAME app.corp.test."
				}
			}
			rr, _ := dns.NewRR(line)
			m.Answer = []dns.RR{rr}
			return m, nil
		}
		m, err := r.ExchangeInternal(context.Background(), new(dns.Msg).SetQuestion("app.corp.test.", dns.TypeA))
		want := dns.RcodeSuccess
		if loop {
			want = dns.RcodeServerFailure
		}
		if err != nil || m.Rcode != want || calls != 2 {
			t.Fatalf("loop=%v calls=%d m=%v err=%v", loop, calls, m, err)
		}
		r.Close()
	}
}
