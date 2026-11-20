package resolve

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"

	"github.com/mythologyli/zju-connect/client"
)

func TestResolveVPNDoesNotUsePublicCacheOrSecondaryDNS(t *testing.T) {
	for _, remote := range []bool{false, true} {
		r := NewResolver(nil, "10.0.0.53", "", 60, nil, nil, remote)
		var publicQueries atomic.Int32
		r.secondaryResolver = &net.Resolver{PreferGo: true, Dial: func(context.Context, string, string) (net.Conn, error) {
			publicQueries.Add(1)
			return nil, errors.New("public DNS must not be called")
		}}
		fail := &net.Resolver{PreferGo: true, Dial: func(context.Context, string, string) (net.Conn, error) {
			return nil, errors.New("gateway DNS unavailable")
		}}
		r.remoteUDPResolver, r.remoteTCPResolver = fail, fail
		r.setDNSCache("private.test", net.ParseIP("203.0.113.10"))
		if _, ip, err := r.ResolveVPN(context.Background(), "private.test"); err == nil || ip != nil {
			t.Fatalf("remote=%v: strict resolver used public cache or fallback: %v %v", remote, ip, err)
		}
		if publicQueries.Load() != 0 {
			t.Fatal("query leaked to public resolver")
		}
		r.Close()
	}
}

func TestResolveVPNPreservesOriginalDomainAuthorization(t *testing.T) {
	r := NewResolver(nil, "", "", 60,
		client.DomainResources{"private.test": {{Protocol: "tcp", PortMin: 443, PortMax: 443}}},
		map[string][]net.IP{"private.test": {net.ParseIP("10.0.0.8")}}, false)
	defer r.Close()
	ctx, ip, err := r.ResolveVPN(context.Background(), "Private.Test.")
	if err != nil || !ip.Equal(net.ParseIP("10.0.0.8")) {
		t.Fatalf("%v %v", ip, err)
	}
	rules, ok := ctx.Value(ContextKeyDomainResource).([]client.DomainResource)
	if !ok || len(rules) != 1 || rules[0].PortMin != 443 || ctx.Value(ContextKeyResolveHost) != "private.test" {
		t.Fatal("lost original domain authorization")
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := r.ResolveVPN(canceled, "private.test"); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	r.Close()
	if _, _, err := r.ResolveVPN(context.Background(), "private.test"); !errors.Is(err, net.ErrClosed) {
		t.Fatal(err)
	}
}

func TestResolveVPNNormalizesIDNAForRulesAndStaticDNS(t *testing.T) {
	r := NewResolver(nil, "", "", 60, client.DomainResources{"*.例子.测试": {{Protocol: "tcp", PortMin: 443, PortMax: 443}}}, map[string][]net.IP{"应用.例子.测试.": {net.ParseIP("10.0.0.8")}}, false)
	defer r.Close()
	ctx, ip, err := r.ResolveVPN(context.Background(), "应用.例子.测试.")
	if err != nil || !ip.Equal(net.ParseIP("10.0.0.8")) {
		t.Fatalf("%v %v", ip, err)
	}
	if rules, _ := ctx.Value(ContextKeyDomainResource).([]client.DomainResource); len(rules) != 1 {
		t.Fatal("IDNA wildcard lost authorization")
	}
}
