package resolve

import (
	"context"
	"errors"
	"net"

	"github.com/mythologyli/zju-connect/client"
)

// ResolveVPN uses only gateway static records and the tunnel DNS. It deliberately
// does not consume the split resolver's cache, which can contain public answers.
func (r *Resolver) ResolveVPN(ctx context.Context, host string) (context.Context, net.IP, error) {
	if err := ctx.Err(); err != nil {
		return ctx, nil, err
	}
	r.resolutionMu.Lock()
	closed := r.resolutionClosed
	r.resolutionMu.Unlock()
	if closed {
		return ctx, nil, net.ErrClosed
	}
	host = normalizeHostname(host)
	if host == "" {
		return ctx, nil, errors.New("empty VPN DNS name")
	}
	ctx = context.WithValue(ctx, ContextKeyResolveHost, host)
	ctx = context.WithValue(ctx, ContextKeyDomainResource, []client.DomainResource(nil))
	ctx = context.WithValue(ctx, contextKey("DOMAIN_RULE"), "")
	ctx = context.WithValue(ctx, ContextKeyIPResource, client.IPResource{})
	if domain, resources, found := matchDomainResource(r.domainIndex, host); found {
		ctx = context.WithValue(ctx, ContextKeyDomainResource, resources)
		ctx = context.WithValue(ctx, contextKey("DOMAIN_RULE"), domain)
	}
	if ips := r.dnsResource[host]; len(ips) > 0 {
		for _, ip := range ips {
			if ip.To4() != nil {
				return ctx, append(net.IP(nil), ip.To4()...), nil
			}
		}
		return ctx, append(net.IP(nil), ips[0]...), nil
	}
	if !r.useRemoteDNS {
		return ctx, nil, errors.New("VPN DNS is not configured")
	}
	ip, err := r.resolveCoordinated(ctx, "vpn:"+host, func(lookupCtx context.Context) (net.IP, error) {
		return r.resolveRemote(lookupCtx, host)
	})
	return ctx, ip, err
}
