package resolve

import (
	"context"
	"github.com/mythologyli/zju-connect/client"
	"net"
	"testing"
)

func TestPreferFakeIPRetainsApplicationIdentityForSharedAddress(t *testing.T) {
	r := NewResolver(nil, "", "", 60, client.DomainResources{
		"one.corp": {{AppID: "one", Protocol: "tcp", PortMin: 443, PortMax: 443}},
		"two.corp": {{AppID: "two", Protocol: "tcp", PortMin: 443, PortMax: 443}},
	}, map[string][]net.IP{"one.corp": {net.ParseIP("10.0.0.1")}, "two.corp": {net.ParseIP("10.0.0.1")}}, false)
	defer r.Close()
	r.PreferFakeIP = true
	ctx := context.WithValue(context.Background(), ContextKeyFakeIP, true)
	seen := map[string]bool{}
	for _, name := range []string{"one", "two"} {
		_, ip, err := r.Resolve(ctx, name+".corp")
		if err != nil {
			t.Fatal(err)
		}
		if seen[ip.String()] {
			t.Fatal("shared fake address")
		}
		seen[ip.String()] = true
		domain, rules, ok := r.IPPool.GetDomain(ip)
		if !ok || domain != name+".corp" || len(rules) != 1 || rules[0].AppID != name {
			t.Fatalf("ownership lost: %s %+v", domain, rules)
		}
	}
	r.ConfigureInternalDomains([]string{"corp"})
	if r.splitDNS || !r.MustUseVPNDNS("one.corp") {
		t.Fatal("Hub configuration changed packet DNS policy or lost ownership")
	}
	_, real, err := r.Resolve(context.Background(), "one.corp")
	if err != nil || !real.Equal(net.ParseIP("10.0.0.1")) {
		t.Fatalf("non-TUN resolver: %v %v", real, err)
	}
}
