package desktop

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mythologyli/zju-connect/client"
	"github.com/mythologyli/zju-connect/dial"
	"github.com/mythologyli/zju-connect/resolve"
	xproxy "golang.org/x/net/proxy"
)

type flowMessages chan Message

func (m flowMessages) Write(b []byte) (int, error) {
	var msg Message
	if err := json.Unmarshal(b, &msg); err != nil {
		return 0, err
	}
	m <- msg
	return len(b), nil
}

func TestFlowReportsSelectedRouteAndSafeFailures(t *testing.T) {
	a, s := aliasFixture(t)
	ip, _ := aliasAnswer(t, a, "a.corp.test")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	c, r, err := a.dialFlow(ctx, "tcp", ip+":443")
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	if r.Route != "vpn" || r.Rule != "domain_resource" || r.Domain != "a.corp.test" || r.Target != "a.corp.test:443" || r.DialAddress != "10.90.0.9:443" || r.PortMin != 443 || r.Failure != "" {
		t.Fatalf("bad domain decision: %+v", r)
	}
	if _, r, err = a.dialFlow(ctx, "tcp", ip+":80"); err == nil || r.Route != "blocked" || r.Rule != "acl" || r.Failure != "denied" {
		t.Fatalf("ACL: %+v %v", r, err)
	}
	s.mu.Lock()
	s.fail = true
	s.mu.Unlock()
	if _, r, err = a.dialFlow(ctx, "tcp", ip+":443"); err == nil || r.Route != "vpn" || r.Failure != "connect" {
		t.Fatalf("failed tunnel: %+v %v", r, err)
	}
	if _, r, err = a.dialFlow(ctx, "tcp", "unknown.corp.test:443"); err == nil || r.Route != "unknown" || r.Rule != "dns" || r.Failure != "dns" {
		t.Fatalf("DNS: %+v %v", r, err)
	}
	a.now = func() time.Time { return time.Now().Add(time.Hour) }
	if _, r, err = a.dialFlow(ctx, "tcp", ip+":443"); err == nil || r.Route != "blocked" || r.Rule != "alias" || r.Failure != "alias" {
		t.Fatalf("expired alias: %+v %v", r, err)
	}
}

func TestFlowPreservesNormalDNSAndDirectIPRouting(t *testing.T) {
	s := &aliasTestStack{}
	ips := []client.IPResource{{IPMin: net.ParseIP("10.90.0.8"), IPMax: net.ParseIP("10.90.0.9"), PortMin: 443, PortMax: 444, Protocol: "tcp"}}
	r := resolve.NewResolver(s, "", "", 60, client.DomainResources{"a.corp.test": {{PortMin: 443, PortMax: 443, Protocol: "tcp"}}}, map[string][]net.IP{"a.corp.test": {net.ParseIP("10.90.0.9")}}, false)
	r.EnableSplitDNS([]string{"corp.test"})
	defer r.Close()
	a := newCaptureAliases(r, ips, dial.NewDialer(s, r, ips, false, ""))
	for _, target := range []string{"a.corp.test:443", "10.90.0.8:444"} {
		c, result, err := a.dialFlow(context.Background(), "tcp", target)
		if err != nil {
			t.Fatal(err)
		}
		c.Close()
		if result.Target != target || result.Route != "vpn" {
			t.Fatalf("%s: %+v", target, result)
		}
		if target == "a.corp.test:443" && (result.Domain != "a.corp.test" || result.Rule != "domain_resource") {
			t.Fatalf("domain rule lost: %+v", result)
		}
		if target == "10.90.0.8:444" && (result.IPMin != "10.90.0.8" || result.PortMax != 444 || result.Rule != "ip_resource") {
			t.Fatalf("IP rule lost: %+v", result)
		}
	}
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, e := ln.Accept()
		if e == nil {
			io.WriteString(c, "direct")
			c.Close()
		}
	}()
	c, result, err := a.dialFlow(context.Background(), "tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	body, err := io.ReadAll(c)
	if err != nil || string(body) != "direct" || result.Route != "direct" || result.Rule != "default" {
		t.Fatalf("direct: %+v %q %v", result, body, err)
	}
}

func TestFlowPrivateSOCKSAuthenticatesAndCorrelatesDNSFailures(t *testing.T) {
	a, _ := aliasFixture(t)
	ip, _ := aliasAnswer(t, a, "a.corp.test")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	messages := make(flowMessages, 32)
	c := &control{ctx: ctx, cancel: cancel, session: "fixture", encoder: json.NewEncoder(messages)}
	cfg := Config{SocksUser: "hub", SocksPassword: strings.Repeat("a", 64)}
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go newDesktopSOCKS(c, cfg, a).Serve(ln)
	var wg sync.WaitGroup
	for i := 1; i <= 12; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			d, _ := xproxy.SOCKS5("tcp", ln.Addr().String(), &xproxy.Auth{User: "hub/" + strconv.Itoa(id), Password: cfg.SocksPassword}, nil)
			target := ip + ":443"
			if id%2 == 0 {
				target = "unknown.corp.test:443"
			}
			dialCtx, stop := context.WithTimeout(ctx, 2*time.Second)
			defer stop()
			conn, err := d.(xproxy.ContextDialer).DialContext(dialCtx, "tcp", target)
			if conn != nil {
				conn.Close()
			}
			if (err == nil) != (id%2 == 1) {
				t.Errorf("request %d error=%v", id, err)
			}
		}(i)
	}
	wg.Wait()
	seen := map[string]bool{}
	for i := 0; i < 12; i++ {
		select {
		case msg := <-messages:
			id, _ := strconv.Atoi(msg.RequestID)
			if seen[msg.RequestID] || id < 1 || id > 12 || msg.Type != "flow_result" || msg.Flow == nil {
				t.Fatalf("wrong correlation: %+v", msg)
			}
			seen[msg.RequestID] = true
			if (msg.Flow.Failure == "dns") != (id%2 == 0) {
				t.Fatalf("result mixed between requests: %+v", msg.Flow)
			}
		case <-time.After(time.Second):
			t.Fatal("missing flow result")
		}
	}
	for _, auth := range []xproxy.Auth{{User: "hub/13", Password: "wrong"}, {User: "hub/13/14", Password: cfg.SocksPassword}} {
		d, _ := xproxy.SOCKS5("tcp", ln.Addr().String(), &auth, nil)
		if conn, err := d.Dial("tcp", ip+":443"); err == nil {
			conn.Close()
			t.Fatal("invalid private credentials accepted")
		}
	}
	select {
	case <-messages:
		t.Fatal("unauthenticated flow emitted")
	default:
	}
}
