package desktop

import (
	"context"
	"errors"
	"time"

	"github.com/miekg/dns"
	"github.com/mythologyli/zju-connect/client"
	"github.com/mythologyli/zju-connect/resolve"
)

type dnsReply struct {
	packet  []byte
	aliases []DNSAlias
}
type dnsExchange func(context.Context, []byte, bool, string) (dnsReply, error)

func dnsHandler(r *resolve.Resolver, ips []client.IPResource, aliases *captureAliases) dnsExchange {
	return func(ctx context.Context, packet []byte, capture bool, prefix string) (dnsReply, error) {
		var reply dnsReply
		if prefix != "" && (!capture || aliases == nil) {
			return reply, errors.New("alias mode requires capture DNS")
		}
		q := new(dns.Msg)
		if err := q.Unpack(packet); err != nil {
			return reply, errors.New("invalid DNS request")
		}
		m, err := r.ExchangeInternal(ctx, q)
		if err != nil {
			return reply, err
		}
		if prefix != "" {
			m, reply.aliases, err = aliases.answer(q, m, prefix)
			if err != nil {
				return reply, err
			}
		} else if capture {
			m = captureDNSAnswer(q, m, ips, r.MustUseVPNDNS)
		}
		reply.packet, err = m.Pack()
		return reply, err
	}
}

func (c *control) setDNSHandler(handler dnsExchange) {
	c.dnsMu.Lock()
	defer c.dnsMu.Unlock()
	c.dnsHandler = handler
	c.dnsPending = make(map[string]context.CancelFunc)
}

// Stop accepting RPCs before waiting so the scanner cannot race Add with Wait.
func (c *control) stopDNS() {
	c.dnsMu.Lock()
	c.dnsHandler = nil
	for _, cancel := range c.dnsPending {
		cancel()
	}
	c.dnsMu.Unlock()
	c.dnsWG.Wait()
}

func (c *control) acceptDNS(m Message) bool {
	if len(m.RequestID) == 0 || len(m.RequestID) > 20 {
		return false
	}
	for _, b := range m.RequestID {
		if b < '0' || b > '9' {
			return false
		}
	}
	c.dnsMu.Lock()
	if m.Type == "dns_cancel" {
		if cancel := c.dnsPending[m.RequestID]; cancel != nil {
			cancel()
		}
		c.dnsMu.Unlock()
		return true
	}
	if _, exists := c.dnsPending[m.RequestID]; exists {
		c.dnsMu.Unlock()
		return false
	}
	if len(m.DNS) < 12 || len(m.DNS) > MaxDNSMessage {
		c.dnsMu.Unlock()
		return false
	}
	handler := c.dnsHandler
	if handler == nil || len(c.dnsPending) >= MaxDNSRequests || c.ctx.Err() != nil {
		c.dnsMu.Unlock()
		_ = c.emit(Message{Type: "dns_result", RequestID: m.RequestID, Error: "DNS service is unavailable or busy"})
		return true
	}
	ctx, cancel := context.WithTimeout(c.ctx, 6*time.Second)
	c.dnsPending[m.RequestID] = cancel
	c.dnsWG.Add(1)
	c.dnsMu.Unlock()
	go func() {
		defer c.dnsWG.Done()
		defer cancel()
		defer func() { c.dnsMu.Lock(); delete(c.dnsPending, m.RequestID); c.dnsMu.Unlock() }()
		reply, err := handler(ctx, m.DNS, m.CaptureDNS, m.CapturePrefix)
		res := Message{Type: "dns_result", RequestID: m.RequestID, DNS: reply.packet, DNSAliases: reply.aliases}
		if err != nil || len(reply.packet) < 12 || len(reply.packet) > MaxDNSMessage || len(reply.aliases) > 32 {
			res.DNS = nil
			res.DNSAliases = nil
			res.Error = "VPN DNS query failed"
		}
		if c.ctx.Err() == nil {
			_ = c.emit(res)
		}
	}()
	return true
}
