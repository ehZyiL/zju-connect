package desktop

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/mythologyli/zju-connect/client"
	"github.com/mythologyli/zju-connect/dial"
	"github.com/mythologyli/zju-connect/internal/ippool"
	"github.com/mythologyli/zju-connect/internal/ipresource"
	"github.com/mythologyli/zju-connect/resolve"
)

const maxAliasTTL = 60

type aliasTarget struct {
	Name    string
	IP      netip.Addr
	Expires time.Time
}

// captureAliases uses a separate instance of the upstream IP pool. In
// particular it never uses Resolver.IPPool's real-IP-to-domain associations,
// which cannot distinguish two resource names sharing the same address.
type captureAliases struct {
	mu       sync.Mutex
	prefix   netip.Prefix
	pool     *ippool.IPPool[aliasTarget]
	resolver *resolve.Resolver
	rules    []client.IPResource
	dialer   *dial.Dialer
	now      func() time.Time
}

func newCaptureAliases(r *resolve.Resolver, rules []client.IPResource, d *dial.Dialer) *captureAliases {
	return &captureAliases{resolver: r, rules: rules, dialer: d, now: aliasNow}
}

// configure is called only by the private DNS control channel. One worker
// generation can own one pool; switching pools needs a new VPN session.
func (a *captureAliases) configure(cidr string) error {
	p, err := netip.ParsePrefix(cidr)
	if err != nil || p != p.Masked() || p.Bits() < 20 || p.Bits() > 24 || !netip.MustParsePrefix(CaptureAliasBlock).Contains(p.Addr()) || p.Overlaps(netip.MustParsePrefix(resolve.FakeIPPrefix)) {
		return errors.New("capture alias range must be an aligned /20–/24 inside " + CaptureAliasBlock + " without overlapping the resolver pool")
	}
	if a.pool != nil {
		if a.prefix != p {
			return errors.New("capture alias range cannot change within a worker session")
		}
		return nil
	}
	lo := p.Addr()
	hiBytes := lo.As4()
	hostBits := uint32(1) << (32 - p.Bits())
	last := uint32(hiBytes[0])<<24 | uint32(hiBytes[1])<<16 | uint32(hiBytes[2])<<8 | uint32(hiBytes[3]) | hostBits - 1
	hi := netip.AddrFrom4([4]byte{byte(last >> 24), byte(last >> 16), byte(last >> 8), byte(last)})
	for _, rule := range a.rules {
		rlo, ok1 := netip.AddrFromSlice(rule.IPMin.To4())
		rhi, ok2 := netip.AddrFromSlice(rule.IPMax.To4())
		if ok1 && ok2 && lo.Compare(rhi) <= 0 && hi.Compare(rlo) >= 0 {
			return errors.New("capture alias range overlaps a VPN resource")
		}
	}
	pool, err := ippool.NewIPPool[aliasTarget](cidr)
	if err != nil {
		return err
	}
	a.pool, a.prefix = pool, p
	return nil
}

func nameKey(name string) string { return strings.TrimSuffix(strings.ToLower(name), ".") }

func (a *captureAliases) allowedNameOrIP(name string, ip net.IP) bool {
	ip4 := ip.To4()
	if ip4 == nil || !ip.IsGlobalUnicast() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || a.prefix.Contains(netip.AddrFrom4([4]byte{ip4[0], ip4[1], ip4[2], ip4[3]})) {
		return false
	}
	ctx := a.resolver.DomainContext(context.Background(), name)
	if rules, ok := ctx.Value(resolve.ContextKeyDomainResource).([]client.DomainResource); ok {
		for _, r := range rules {
			if (r.Protocol == "tcp" || r.Protocol == "all") && r.PortMin > 0 && r.PortMax >= r.PortMin && r.PortMax <= 65535 {
				return true
			}
		}
	}
	v, _ := ipresource.IPv4Uint32(ip4)
	for _, r := range a.rules {
		lo, ok1 := ipresource.IPv4Uint32(r.IPMin)
		hi, ok2 := ipresource.IPv4Uint32(r.IPMax)
		if ok1 && ok2 && lo <= v && v <= hi && (r.Protocol == "tcp" || r.Protocol == "all") && r.PortMin > 0 && r.PortMax >= r.PortMin && r.PortMax <= 65535 {
			return true
		}
	}
	return false
}

// answer returns aliases which the platform must install before publishing the
// DNS packet. The platform restores real destinations for unselected programs;
// selected programs keep the synthetic address until this worker checks it.
func (a *captureAliases) answer(q, m *dns.Msg, cidr string) (*dns.Msg, []DNSAlias, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.now()
	if now.IsZero() {
		return nil, nil, errors.New("capture alias clock unavailable")
	}
	if err := a.configure(cidr); err != nil {
		return nil, nil, err
	}
	if m.Rcode != dns.RcodeSuccess || len(q.Question) != 1 {
		return m, nil, nil
	}
	if q.Question[0].Qtype != dns.TypeA {
		// Auxiliary address records would be cached under the wrong authority.
		m = m.Copy()
		m.Extra = nil
		for _, section := range []*[]dns.RR{&m.Answer, &m.Ns} {
			kept := (*section)[:0]
			for _, rr := range *section {
				if rr.Header().Rrtype != dns.TypeA {
					kept = append(kept, rr)
				}
			}
			*section = kept
		}
		return captureDNSAnswer(q, m, a.rules, a.resolver.MustUseVPNDNS), nil, nil
	}
	if !a.resolver.MustUseVPNDNS(q.Question[0].Name) {
		return new(dns.Msg).SetRcode(q, dns.RcodeRefused), nil, nil
	}
	// Flatten only A lookups. Keeping a shared canonical owner would let a
	// system cache reuse domain A's fake address while resolving domain B.
	original := nameKey(q.Question[0].Name)
	current := original
	ttl := uint32(maxAliasTTL)
	seen := map[string]bool{}
	var addresses []*dns.A
	for hops := 0; hops < 16; hops++ {
		if seen[current] {
			return new(dns.Msg).SetRcode(q, dns.RcodeServerFailure), nil, nil
		}
		seen[current] = true
		next := ""
		for _, rr := range m.Answer {
			if nameKey(rr.Header().Name) != current {
				continue
			}
			switch record := rr.(type) {
			case *dns.CNAME:
				if next != "" && next != nameKey(record.Target) {
					return new(dns.Msg).SetRcode(q, dns.RcodeServerFailure), nil, nil
				}
				next = nameKey(record.Target)
				if record.Hdr.Ttl < ttl {
					ttl = record.Hdr.Ttl
				}
			case *dns.A:
				addresses = append(addresses, record)
				if record.Hdr.Ttl < ttl {
					ttl = record.Hdr.Ttl
				}
			}
		}
		if len(addresses) > 0 {
			if next != "" {
				return new(dns.Msg).SetRcode(q, dns.RcodeServerFailure), nil, nil
			}
			break
		}
		if next == "" {
			if current != original {
				return new(dns.Msg).SetRcode(q, dns.RcodeServerFailure), nil, nil
			}
			return captureDNSAnswer(q, m, a.rules, a.resolver.MustUseVPNDNS), nil, nil
		}
		// A complete VPN-provided CNAME chain may end outside the configured
		// suffix: it is flattened here, so the client never publicly resolves
		// that canonical name. An incomplete chain fails instead of escaping.
		if _, valid := dns.IsDomainName(dns.Fqdn(next)); !valid {
			return new(dns.Msg).SetRcode(q, dns.RcodeServerFailure), nil, nil
		}
		current = next
	}
	if len(addresses) == 0 || len(addresses) > 32 {
		return new(dns.Msg).SetRcode(q, dns.RcodeServerFailure), nil, nil
	}
	for _, record := range addresses {
		if !a.allowedNameOrIP(original, record.A) {
			return new(dns.Msg).SetRcode(q, dns.RcodeServerFailure), nil, nil
		}
	}
	response := new(dns.Msg).SetReply(q)
	response.RecursionAvailable = true
	aliases := make([]DNSAlias, 0, len(addresses))
	for _, record := range addresses {
		realIP, _ := netip.AddrFromSlice(record.A.To4())
		key := original + "/" + realIP.String()
		// A TTL=0 answer can still be used for the immediate connection, but is
		// never advertised as cacheable. No address is reused for another name.
		lifetime := ttl
		if lifetime == 0 {
			lifetime = 1
		}
		target := aliasTarget{Name: original, IP: realIP, Expires: now.Add(time.Duration(lifetime) * time.Second)}
		fakeIP, err := a.pool.AllocateIP(key, target)
		if err != nil {
			return nil, nil, err
		}
		// A shorter later response must not invalidate an earlier response
		// that another application is still entitled to cache. Identity and
		// actual destination never change for this alias.
		if _, old, ok := a.pool.GetDomain(fakeIP); ok && old.Expires.After(target.Expires) {
			target.Expires = old.Expires
		}
		if err = a.pool.SetIPDomain(fakeIP, key, target); err != nil {
			return nil, nil, err
		}
		response.Answer = append(response.Answer, &dns.A{Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl}, A: fakeIP})
		aliases = append(aliases, DNSAlias{Address: fakeIP.String(), Original: realIP.String(), TTL: lifetime})
	}
	return response, aliases, nil
}

func (a *captureAliases) Dial(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return nil, err
	}
	a.mu.Lock()
	inside := a.pool != nil && a.prefix.Contains(ip)
	var target aliasTarget
	valid := false
	if inside {
		_, target, valid = a.pool.GetDomain(net.ParseIP(host))
		now := a.now()
		valid = valid && !now.IsZero() && now.Before(target.Expires)
	}
	a.mu.Unlock()
	if !inside {
		return a.dialer.DialIPPort(ctx, network, address)
	}
	if !valid {
		return nil, errCaptureAlias
	}
	if _, err = strconv.ParseUint(port, 10, 16); err != nil {
		return nil, err
	}
	ctx = a.resolver.DomainContext(ctx, target.Name)
	return a.dialer.DialVPNIPPort(ctx, network, net.JoinHostPort(target.IP.String(), port))
}
