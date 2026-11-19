package resolve

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mythologyli/zju-connect/client"
	"github.com/patrickmn/go-cache"
)

func TestSplitDNSNeverFallsBackForInternalNames(t *testing.T) {
	var remote, local atomic.Int32
	failing := func(count *atomic.Int32) *net.Resolver {
		return &net.Resolver{PreferGo: true, Dial: func(context.Context, string, string) (net.Conn, error) {
			count.Add(1)
			return nil, errors.New("unavailable")
		}}
	}
	r := &Resolver{remoteUDPResolver: failing(&remote), remoteTCPResolver: failing(&remote), secondaryResolver: failing(&local), domainIndex: newDomainResourceIndex(client.DomainResources{"resource.test": {{PortMin: 1, PortMax: 65535, Protocol: "tcp"}}}), dnsCache: cache.New(time.Minute, 0), useRemoteDNS: true}
	r.EnableSplitDNS([]string{"corp.test"})
	for _, host := range []string{"app.corp.test", "app.resource.test"} {
		if _, _, err := r.Resolve(context.Background(), host); err == nil {
			t.Fatal("internal lookup unexpectedly succeeded")
		}
	}
	if remote.Load() == 0 || local.Load() != 0 {
		t.Fatalf("internal query leaked: remote=%d local=%d", remote.Load(), local.Load())
	}
	before := remote.Load()
	_, _, _ = r.Resolve(context.Background(), "public.example")
	if local.Load() == 0 || remote.Load() != before {
		t.Fatal("public query used VPN DNS")
	}
	local.Store(0)
	r.useRemoteDNS = false
	_, _, err := r.Resolve(context.Background(), "app.corp.test")
	if err == nil || local.Load() != 0 {
		t.Fatal("missing VPN DNS used public fallback")
	}
	if r.MustUseVPNDNS("notcorp.test") {
		t.Fatal("suffix ignored label boundary")
	}
}
