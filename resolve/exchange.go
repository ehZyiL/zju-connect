package resolve

import (
	"context"
	"errors"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/mythologyli/zju-connect/stack"
)

type dnsExchangeFunc func(context.Context, string, *dns.Msg) (*dns.Msg, error)

// ExchangeInternal preserves DNS records, RCODEs and TTLs. It is deliberately
// limited to the same internal names as Resolve: public queries must remain on
// the host's original resolver, never recurse through a future local DNS link.
// Unlike Resolve's single-IP cache, this path does not cache rewritten answers.
func (r *Resolver) exchangeInternalOne(ctx context.Context, q *dns.Msg, requireInternal bool) (*dns.Msg, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	r.resolutionMu.Lock()
	closed := r.resolutionClosed
	r.resolutionMu.Unlock()
	if closed {
		return nil, net.ErrClosed
	}
	answer := func(code int) *dns.Msg {
		m := new(dns.Msg).SetRcode(q, code)
		m.RecursionAvailable = true
		return m
	}
	if q.Response || len(q.Question) != 1 {
		return answer(dns.RcodeFormatError), nil
	}
	if q.Opcode != dns.OpcodeQuery {
		return answer(dns.RcodeNotImplemented), nil
	}
	question := q.Question[0]
	if question.Qclass != dns.ClassINET || question.Qtype == dns.TypeAXFR || question.Qtype == dns.TypeIXFR || q.IsTsig() != nil {
		return answer(dns.RcodeRefused), nil
	}
	host := normalizeHostname(question.Name)
	if requireInternal && !r.MustUseVPNDNS(host) {
		return answer(dns.RcodeRefused), nil
	}
	if ips, ok := r.dnsResource[host]; ok && (question.Qtype == dns.TypeA || question.Qtype == dns.TypeAAAA) {
		m := answer(dns.RcodeSuccess)
		m.Authoritative = true
		for _, ip := range ips {
			hdr := dns.RR_Header{Name: question.Name, Rrtype: question.Qtype, Class: dns.ClassINET, Ttl: 60}
			if question.Qtype == dns.TypeA && ip.To4() != nil {
				m.Answer = append(m.Answer, &dns.A{Hdr: hdr, A: ip.To4()})
			} else if question.Qtype == dns.TypeAAAA && ip.To4() == nil && ip.To16() != nil {
				m.Answer = append(m.Answer, &dns.AAAA{Hdr: hdr, AAAA: ip.To16()})
			}
		}
		return m, nil
	}
	if !r.useRemoteDNS || r.wireExchange == nil {
		return answer(dns.RcodeServerFailure), nil
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	r.tcpLock.RLock()
	preferTCP := r.useTCP
	r.tcpLock.RUnlock()
	if !preferTCP {
		udpCtx, stop := context.WithTimeout(ctx, remoteDNSTCPFallbackDelay)
		m, err := r.wireExchange(udpCtx, "udp", q)
		stop()
		if err == nil && validDNSReply(q, m) && !m.Truncated {
			return m, nil
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
	}
	m, err := r.wireExchange(ctx, "tcp", q)
	if err != nil || !validDNSReply(q, m) || m.Truncated {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return answer(dns.RcodeServerFailure), nil
	}
	if !preferTCP {
		r.preferTCPTemporarily()
	}
	return m, nil
}

func validDNSReply(q, m *dns.Msg) bool {
	return m != nil && m.Response && m.Id == q.Id && m.Opcode == q.Opcode && len(m.Question) == 1 &&
		strings.EqualFold(m.Question[0].Name, q.Question[0].Name) && m.Question[0].Qtype == q.Question[0].Qtype && m.Question[0].Qclass == q.Question[0].Qclass
}

func tunnelDNSExchange(s stack.Stack, server string) dnsExchangeFunc {
	return func(ctx context.Context, network string, q *dns.Msg) (*dns.Msg, error) {
		ip := net.ParseIP(server).To4()
		if ip == nil {
			return nil, errors.New("VPN DNS is unavailable")
		}
		var conn net.Conn
		var err error
		if network == "udp" {
			conn, err = s.DialUDP(ctx, &net.UDPAddr{IP: ip, Port: 53})
		} else {
			conn, err = s.DialTCP(ctx, &net.TCPAddr{IP: ip, Port: 53})
		}
		if err != nil {
			return nil, err
		}
		defer conn.Close()
		stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
		defer stop()
		client := &dns.Client{Net: network, Timeout: 5 * time.Second, UDPSize: 4096}
		m, _, err := client.ExchangeWithConnContext(ctx, q, &dns.Conn{Conn: conn})
		return m, err
	}
}
