package dial

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/mythologyli/zju-connect/client"
	"github.com/mythologyli/zju-connect/internal/ippool"
	"github.com/mythologyli/zju-connect/internal/ipresource"
	"github.com/mythologyli/zju-connect/internal/zcdns"
	"github.com/mythologyli/zju-connect/resolve"
)

func TestMatchesIPResourcePreservesRangePortAndProtocolRules(t *testing.T) {
	resources := []client.IPResource{{
		IPMin:    net.IPv4(10, 0, 0, 1),
		IPMax:    net.IPv4(10, 0, 0, 10),
		PortMin:  443,
		PortMax:  443,
		Protocol: "tcp",
	}}
	index := ipresource.New(resources)

	tests := []struct {
		name    string
		ip      net.IP
		network string
		port    int
		want    bool
	}{
		{name: "match", ip: net.IPv4(10, 0, 0, 5), network: "tcp", port: 443, want: true},
		{name: "outside range", ip: net.IPv4(10, 0, 0, 11), network: "tcp", port: 443},
		{name: "wrong port", ip: net.IPv4(10, 0, 0, 5), network: "tcp", port: 80},
		{name: "wrong protocol", ip: net.IPv4(10, 0, 0, 5), network: "udp", port: 443},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := matchesIPResource(index, test.ip, test.network, test.port); got != test.want {
				t.Fatalf("matchesIPResource() = %v, want %v", got, test.want)
			}
		})
	}
}

func TestDialIPPortSelectsMatchingDomainResource(t *testing.T) {
	resources := []client.DomainResource{
		{PortMin: 443, PortMax: 443, Protocol: "tcp", AppID: "https"},
		{PortMin: 80, PortMax: 80, Protocol: "tcp", AppID: "http"},
	}
	ctx := context.WithValue(context.Background(), resolve.ContextKeyDomainResource, resources)
	dialer := &Dialer{stack: &capturingStack{}, resourceIndex: ipresource.New(nil)}

	_, err := dialer.DialIPPort(ctx, "tcp", "121.194.4.13:443")
	if err != nil {
		t.Fatalf("DialIPPort() error = %v", err)
	}
	if got := dialer.stack.(*capturingStack).domainResource.AppID; got != "https" {
		t.Fatalf("selected AppID = %q, want https", got)
	}
}

func TestDialIPPortPrefersTCPTunnelResourceOverOverlappingL3Resource(t *testing.T) {
	resources := []client.DomainResource{
		{PortMin: 443, PortMax: 443, Protocol: "tcp", AppID: "l3", EnableTCPPrefL3: true},
		{PortMin: 443, PortMax: 443, Protocol: "tcp", AppID: "tcp"},
	}
	ctx := context.WithValue(context.Background(), resolve.ContextKeyDomainResource, resources)
	dialer := &Dialer{stack: &capturingStack{}, resourceIndex: ipresource.New(nil)}

	if _, err := dialer.DialIPPort(ctx, "tcp", "121.194.4.13:443"); err != nil {
		t.Fatalf("DialIPPort() error = %v", err)
	}
	if got := dialer.stack.(*capturingStack).domainResource.AppID; got != "tcp" {
		t.Fatalf("selected AppID = %q, want tcp", got)
	}
}

func TestDialIPPortCarriesTCPPrefL3IPResource(t *testing.T) {
	resource := client.IPResource{
		IPMin: net.IPv4(10, 0, 0, 42), IPMax: net.IPv4(10, 0, 0, 42), PortMin: 443, PortMax: 443,
		Protocol: "tcp", AppID: "l3", EnableTCPPrefL3: true,
	}
	stack := &capturingStack{}
	dialer := &Dialer{stack: stack, ipResources: []client.IPResource{resource}, resourceIndex: ipresource.New([]client.IPResource{resource})}

	if _, err := dialer.DialIPPort(context.Background(), "tcp", "10.0.0.42:443"); err != nil {
		t.Fatalf("DialIPPort() error = %v", err)
	}
	if !stack.ipResource.EnableTCPPrefL3 || stack.ipResource.AppID != "l3" {
		t.Fatalf("selected IP resource = %#v, want l3 TCP-prefers-L3", stack.ipResource)
	}
}

type capturingStack struct {
	domainResource client.DomainResource
	ipResource     client.IPResource
}

func (s *capturingStack) Run()                                                {}
func (s *capturingStack) SetupResolve(zcdns.LocalServer)                      {}
func (s *capturingStack) SetupIPPool(*ippool.IPPool[[]client.DomainResource]) {}
func (s *capturingStack) DialTCP(ctx context.Context, _ *net.TCPAddr) (net.Conn, error) {
	if resource, ok := ctx.Value(resolve.ContextKeyDomainResource).(client.DomainResource); ok {
		s.domainResource = resource
	}
	if resource, ok := ctx.Value(resolve.ContextKeyIPResource).(client.IPResource); ok {
		s.ipResource = resource
	}
	return nil, nil
}
func (s *capturingStack) DialUDP(context.Context, *net.UDPAddr) (net.Conn, error) {
	return nil, nil
}

func TestDialVPN_RejectsUnsupportedNetwork(t *testing.T) {
	dialer := &Dialer{stack: &capturingStack{}}
	for _, network := range []string{"udp4", "unix", "icmp", "raw"} {
		var observed Decision
		ctx := WithDecisionObserver(context.Background(), func(d Decision) { observed = d })
		_, err := dialer.DialVPN(ctx, network, "10.0.0.1:443")
		if !errors.Is(err, ErrACLDenied) {
			t.Fatalf("DialVPN(%q) error = %v, want ErrACLDenied", network, err)
		}
		if observed.Route != "blocked" || observed.Rule != "acl" {
			t.Fatalf("observed decision = %+v, want Route: blocked, Rule: acl", observed)
		}
	}
}

func TestDialVPN_RejectsIPv6Targets(t *testing.T) {
	dialer := &Dialer{stack: &capturingStack{}}
	targets := []string{
		"[2001:db8::1]:80",
		"[::1]:8080",
		"2001:db8::1:80",
	}
	for _, target := range targets {
		var observed Decision
		ctx := WithDecisionObserver(context.Background(), func(d Decision) { observed = d })
		_, err := dialer.DialVPN(ctx, "tcp", target)
		if !errors.Is(err, ErrACLDenied) {
			t.Fatalf("DialVPN(%q) error = %v, want ErrACLDenied", target, err)
		}
		if observed.Route != "blocked" || observed.Rule != "acl" {
			t.Fatalf("observed decision = %+v, want Route: blocked, Rule: acl", observed)
		}
	}
}

func TestDialVPN_AuthorizesIPResource(t *testing.T) {
	resource := client.IPResource{
		IPMin: net.IPv4(10, 0, 0, 1), IPMax: net.IPv4(10, 0, 0, 10),
		PortMin: 443, PortMax: 443, Protocol: "tcp", AppID: "intranet",
	}
	stack := &capturingStack{}
	dialer := &Dialer{stack: stack, ipResources: []client.IPResource{resource}, resourceIndex: ipresource.New([]client.IPResource{resource})}

	var observed Decision
	ctx := WithDecisionObserver(context.Background(), func(d Decision) { observed = d })
	_, err := dialer.DialVPN(ctx, "tcp", "10.0.0.5:443")
	if err != nil {
		t.Fatalf("DialVPN() error = %v", err)
	}
	if observed.Route != "vpn" || observed.Rule != "ip_resource" {
		t.Fatalf("observed decision = %+v, want Route: vpn, Rule: ip_resource", observed)
	}
	if stack.ipResource.AppID != "intranet" {
		t.Fatalf("stack ipResource AppID = %q, want intranet", stack.ipResource.AppID)
	}
}

func TestDialVPN_RejectsUnauthorizedIP(t *testing.T) {
	resource := client.IPResource{
		IPMin: net.IPv4(10, 0, 0, 1), IPMax: net.IPv4(10, 0, 0, 10),
		PortMin: 443, PortMax: 443, Protocol: "tcp",
	}
	dialer := &Dialer{stack: &capturingStack{}, ipResources: []client.IPResource{resource}, resourceIndex: ipresource.New([]client.IPResource{resource})}

	cases := []struct {
		network, addr string
	}{
		{"tcp", "10.0.0.11:443"}, // outside IP range
		{"tcp", "10.0.0.5:80"},    // unauthorized port
		{"udp", "10.0.0.5:443"},   // unauthorized protocol
	}
	for _, tc := range cases {
		var observed Decision
		ctx := WithDecisionObserver(context.Background(), func(d Decision) { observed = d })
		_, err := dialer.DialVPN(ctx, tc.network, tc.addr)
		if !errors.Is(err, ErrACLDenied) {
			t.Fatalf("DialVPN(%s, %s) error = %v, want ErrACLDenied", tc.network, tc.addr, err)
		}
		if observed.Route != "blocked" || observed.Rule != "acl" {
			t.Fatalf("observed decision = %+v, want Route: blocked, Rule: acl", observed)
		}
	}
}

func TestDialVPN_AuthorizesDomainResource(t *testing.T) {
	stack := &capturingStack{}
	domains := client.DomainResources{
		"oa.example.com": {{PortMin: 443, PortMax: 443, Protocol: "tcp", AppID: "oa-app"}},
	}
	records := map[string][]net.IP{
		"oa.example.com": {net.IPv4(10, 20, 0, 5)},
	}
	resolver := resolve.NewResolver(stack, "", "", 60, domains, records, false)
	dialer := &Dialer{stack: stack, resolver: resolver, resourceIndex: ipresource.New(nil)}

	var observed Decision
	ctx := WithDecisionObserver(context.Background(), func(d Decision) { observed = d })
	_, err := dialer.DialVPN(ctx, "tcp", "oa.example.com:443")
	if err != nil {
		t.Fatalf("DialVPN() error = %v", err)
	}
	if observed.Route != "vpn" || observed.Rule != "domain_resource" || observed.Host != "oa.example.com" {
		t.Fatalf("observed decision = %+v, want Route: vpn, Rule: domain_resource, Host: oa.example.com", observed)
	}
	if stack.domainResource.AppID != "oa-app" {
		t.Fatalf("stack domainResource AppID = %q, want oa-app", stack.domainResource.AppID)
	}
}

func TestDialVPN_RejectsUnauthorizedDomain(t *testing.T) {
	stack := &capturingStack{}
	records := map[string][]net.IP{
		"public.example.com": {net.IPv4(192, 168, 1, 1)},
	}
	resolver := resolve.NewResolver(stack, "", "", 60, nil, records, false)
	dialer := &Dialer{stack: stack, resolver: resolver, resourceIndex: ipresource.New(nil)}

	var observed Decision
	ctx := WithDecisionObserver(context.Background(), func(d Decision) { observed = d })
	_, err := dialer.DialVPN(ctx, "tcp", "public.example.com:443")
	if !errors.Is(err, ErrACLDenied) {
		t.Fatalf("DialVPN() error = %v, want ErrACLDenied", err)
	}
	if observed.Route != "blocked" || observed.Rule != "acl" {
		t.Fatalf("observed decision = %+v, want Route: blocked, Rule: acl", observed)
	}
}

func TestDialVPN_DomainResolutionFailureDoesNotFallback(t *testing.T) {
	stack := &capturingStack{}
	resolver := resolve.NewResolver(stack, "", "", 60, nil, nil, false)
	dialer := &Dialer{stack: stack, resolver: resolver, resourceIndex: ipresource.New(nil)}

	var observed Decision
	ctx := WithDecisionObserver(context.Background(), func(d Decision) { observed = d })
	_, err := dialer.DialVPN(ctx, "tcp", "nonexistent.test:443")
	if err == nil {
		t.Fatal("DialVPN() expected resolution error, got nil")
	}
	if observed.Route != "blocked" || observed.Rule != "acl" {
		t.Fatalf("observed decision = %+v, want Route: blocked, Rule: acl", observed)
	}
}

func TestDialVPN_DomainResolvingToIPv6Rejected(t *testing.T) {
	stack := &capturingStack{}
	records := map[string][]net.IP{
		"ipv6.example.com": {net.ParseIP("2001:db8::1")},
	}
	resolver := resolve.NewResolver(stack, "", "", 60, nil, records, false)
	dialer := &Dialer{stack: stack, resolver: resolver, resourceIndex: ipresource.New(nil)}

	var observed Decision
	ctx := WithDecisionObserver(context.Background(), func(d Decision) { observed = d })
	_, err := dialer.DialVPN(ctx, "tcp", "ipv6.example.com:80")
	if !errors.Is(err, ErrACLDenied) {
		t.Fatalf("DialVPN() error = %v, want ErrACLDenied", err)
	}
	if observed.Route != "blocked" || observed.Rule != "acl" {
		t.Fatalf("observed decision = %+v, want Route: blocked, Rule: acl", observed)
	}
}
