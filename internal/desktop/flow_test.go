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
	for i := 1; i <= 12; i++ {
		prepareTestFlow(t, c, messages, strconv.Itoa(i))
	}
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

type blockingFlowTestStack struct {
	aliasTestStack
	entered chan struct{}
}

func (s *blockingFlowTestStack) DialTCP(ctx context.Context, addr *net.TCPAddr) (net.Conn, error) {
	if s.entered != nil {
		select {
		case s.entered <- struct{}{}:
		default:
		}
	}
	<-ctx.Done()
	return nil, ctx.Err()
}

func TestVPNOnlySOCKSAllowsAuthorizedDomainAndIP(t *testing.T) {
	a, _ := aliasFixture(t)
	ip, _ := aliasAnswer(t, a, "a.corp.test")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	messages := make(flowMessages, 16)
	c := &control{ctx: ctx, cancel: cancel, session: "fixture", encoder: json.NewEncoder(messages), flowPending: make(map[string]*flowRequest)}
	cfg := Config{SocksUser: "hub", SocksPassword: strings.Repeat("a", 64)}
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go newDesktopVPNOnlySOCKS(c, cfg, a, false).Serve(ln)

	prepareTestFlow(t, c, messages, "1")
	d, _ := xproxy.SOCKS5("tcp", ln.Addr().String(), &xproxy.Auth{User: "hub/1", Password: cfg.SocksPassword}, nil)
	conn, err := d.(xproxy.ContextDialer).DialContext(ctx, "tcp", ip+":443")
	if err != nil {
		t.Fatalf("VPN-only SOCKS failed to connect authorized target: %v", err)
	}
	defer conn.Close()
	body, err := io.ReadAll(conn)
	if err != nil || !strings.HasPrefix(string(body), "vpn:") {
		t.Fatalf("expected vpn payload, got %q %v", body, err)
	}

	select {
	case msg := <-messages:
		if msg.Type != "flow_result" || msg.RequestID != "1" || msg.Flow == nil {
			t.Fatalf("unexpected message: %+v", msg)
		}
		if msg.Flow.Route != "vpn" || msg.Flow.Rule != "domain_resource" || msg.Flow.Failure != "" {
			t.Fatalf("unexpected flow result: %+v", msg.Flow)
		}
	case <-time.After(time.Second):
		t.Fatal("missing flow_result message")
	}
}

func TestVPNOnlySOCKSRejectsUnauthorizedTargetWithRepRuleFailure(t *testing.T) {
	a, _ := aliasFixture(t)
	ip, _ := aliasAnswer(t, a, "a.corp.test")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	messages := make(flowMessages, 16)
	c := &control{ctx: ctx, cancel: cancel, session: "fixture", encoder: json.NewEncoder(messages), flowPending: make(map[string]*flowRequest)}
	cfg := Config{SocksUser: "hub", SocksPassword: strings.Repeat("a", 64)}
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go newDesktopVPNOnlySOCKS(c, cfg, a, false).Serve(ln)

	prepareTestFlow(t, c, messages, "2")
	d, _ := xproxy.SOCKS5("tcp", ln.Addr().String(), &xproxy.Auth{User: "hub/2", Password: cfg.SocksPassword}, nil)
	conn, err := d.(xproxy.ContextDialer).DialContext(ctx, "tcp", ip+":80")
	if conn != nil {
		conn.Close()
		t.Fatal("expected unauthorized dial to be refused, got connection")
	}
	if err == nil {
		t.Fatal("expected error on unauthorized dial, got nil")
	}

	select {
	case msg := <-messages:
		if msg.Type != "flow_result" || msg.RequestID != "2" || msg.Flow == nil {
			t.Fatalf("unexpected message: %+v", msg)
		}
		if msg.Flow.Route != "blocked" || msg.Flow.Rule != "acl" || msg.Flow.Failure != "denied" {
			t.Fatalf("unexpected flow result: %+v", msg.Flow)
		}
	case <-time.After(time.Second):
		t.Fatal("missing flow_result message")
	}
}

func TestWorkerFlowCancelAbortsDialAndFreesSlot(t *testing.T) {
	stack := &blockingFlowTestStack{entered: make(chan struct{}, 1)}
	ips := []client.IPResource{{IPMin: net.ParseIP("10.90.0.8"), IPMax: net.ParseIP("10.90.0.9"), PortMin: 443, PortMax: 443, Protocol: "tcp"}}
	r := resolve.NewResolver(stack, "", "", 60, client.DomainResources{"a.corp.test": {{PortMin: 443, PortMax: 443, Protocol: "tcp"}}}, map[string][]net.IP{"a.corp.test": {net.ParseIP("10.90.0.9")}}, false)
	defer r.Close()
	a := newCaptureAliases(r, ips, dial.NewDialer(stack, r, ips, false, ""))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	messages := make(flowMessages, 16)
	c := &control{ctx: ctx, cancel: cancel, session: "fixture", encoder: json.NewEncoder(messages), flowPending: make(map[string]*flowRequest)}
	cfg := Config{SocksUser: "hub", SocksPassword: strings.Repeat("a", 64)}

	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go newDesktopSOCKS(c, cfg, a).Serve(ln)

	prepareTestFlow(t, c, messages, "1")
	d, _ := xproxy.SOCKS5("tcp", ln.Addr().String(), &xproxy.Auth{User: "hub/1", Password: cfg.SocksPassword}, nil)
	dialCtx, dialCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer dialCancel()

	dialDone := make(chan error, 1)
	go func() {
		conn, err := d.(xproxy.ContextDialer).DialContext(dialCtx, "tcp", "a.corp.test:443")
		if conn != nil {
			conn.Close()
		}
		dialDone <- err
	}()

	select {
	case <-stack.entered:
	case <-time.After(time.Second):
		t.Fatal("dial did not enter stack")
	}

	start := time.Now()
	if !c.accept(Message{Version: Version, Session: "fixture", Type: "flow_cancel", RequestID: "1"}) {
		t.Fatal("accept flow_cancel rejected")
	}

	select {
	case err := <-dialDone:
		elapsed := time.Since(start)
		if elapsed > 100*time.Millisecond {
			t.Fatalf("abort took %v > 100ms", elapsed)
		}
		if err == nil {
			t.Fatal("dial succeeded, want canceled error")
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("dial did not abort on flow_cancel")
	}

	select {
	case msg := <-messages:
		if msg.Type != "flow_result" || msg.RequestID != "1" || msg.Flow == nil || msg.Flow.Failure != "canceled" {
			t.Fatalf("unexpected flow_result message: %+v", msg)
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("missing flow_result message")
	}
}

func TestRunReadyMessageIncludesVPNAddressAndCapabilities(t *testing.T) {
	m := Message{
		Version:       Version,
		Session:       "fixture-ready",
		Type:          "ready",
		Address:       "127.0.0.1:12345",
		VPNAddress:    "127.0.0.1:23456",
		Capabilities:  []string{"strict_vpn", "flow_cancel"},
		FlowReporting: true,
	}
	data, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}
	var decoded Message
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if decoded.Address != "127.0.0.1:12345" {
		t.Errorf("Address = %q, want 127.0.0.1:12345", decoded.Address)
	}
	if decoded.VPNAddress != "127.0.0.1:23456" {
		t.Errorf("VPNAddress = %q, want 127.0.0.1:23456", decoded.VPNAddress)
	}
	if len(decoded.Capabilities) != 2 || decoded.Capabilities[0] != "strict_vpn" || decoded.Capabilities[1] != "flow_cancel" {
		t.Errorf("Capabilities = %v, want [strict_vpn, flow_cancel]", decoded.Capabilities)
	}
}

func prepareTestFlow(t *testing.T, c *control, messages flowMessages, id string) {
	t.Helper()
	if !c.accept(Message{Version: Version, Session: c.session, Type: "flow_prepare", RequestID: id, Deadline: time.Now().Add(5 * time.Second).UnixMilli()}) {
		t.Fatal("prepare rejected")
	}
	select {
	case m := <-messages:
		if m.Type != "flow_ready" || m.RequestID != id || m.Error != "" {
			t.Fatalf("prepare result: %+v", m)
		}
	case <-time.After(time.Second):
		t.Fatal("prepare acknowledgement missing")
	}
}
