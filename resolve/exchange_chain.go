package resolve

import (
	"context"
	"github.com/miekg/dns"
	"strings"
	"time"
)

// ExchangeInternal completes bounded address CNAME chains on the selected
// gateway. A canonical name is never delegated to the host/public resolver.
func (r *Resolver) ExchangeInternal(ctx context.Context, q *dns.Msg) (*dns.Msg, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	m, err := r.exchangeInternalOne(ctx, q, true)
	if err != nil || m.Rcode != dns.RcodeSuccess || len(q.Question) != 1 {
		return m, err
	}
	typ := q.Question[0].Qtype
	if typ != dns.TypeA && typ != dns.TypeAAAA {
		return m, nil
	}
	original := strings.ToLower(dns.Fqdn(q.Question[0].Name))
	current := original
	seen := map[string]bool{}
	fail := func() (*dns.Msg, error) { return new(dns.Msg).SetRcode(q, dns.RcodeServerFailure), nil }
	scan := func(records []dns.RR) (string, bool, bool) {
		next := ""
		found := false
		for _, rr := range records {
			if !strings.EqualFold(rr.Header().Name, current) {
				continue
			}
			if rr.Header().Rrtype == typ {
				found = true
			}
			if c, ok := rr.(*dns.CNAME); ok {
				name := strings.ToLower(dns.Fqdn(c.Target))
				if _, valid := dns.IsDomainName(name); !valid {
					return "", false, false
				}
				if next != "" && next != name {
					return "", false, false
				}
				next = name
			}
		}
		return next, found, !(found && next != "")
	}
	for range 16 {
		if seen[current] {
			return fail()
		}
		seen[current] = true
		next, found, valid := scan(m.Answer)
		if !valid {
			return fail()
		}
		if !found && next == "" && current != original {
			follow := q.Copy()
			follow.Question[0].Name = current
			reply, e := r.exchangeInternalOne(ctx, follow, false)
			if e != nil {
				return nil, e
			}
			if reply.Rcode != dns.RcodeSuccess {
				m.Rcode = reply.Rcode
				m.Ns = reply.Ns
				return m, nil
			}
			m.Answer = append(m.Answer, reply.Answer...)
			m.Ns = reply.Ns
			m.Extra = nil
			if len(m.Answer) > 512 {
				return fail()
			}
			next, found, valid = scan(reply.Answer)
			if !valid {
				return fail()
			}
		}
		if found || next == "" {
			return m, nil
		}
		current = next
	}
	return fail()
}
