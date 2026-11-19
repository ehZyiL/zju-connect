package desktop

import (
	"context"
	"errors"
	"io"
	"net"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/mythologyli/zju-connect/client"
	"github.com/mythologyli/zju-connect/dial"
	"github.com/mythologyli/zju-connect/resolve"
	"github.com/mythologyli/zju-connect/stack"
	"github.com/things-go/go-socks5"
	xproxy "golang.org/x/net/proxy"
)

type aliasTestStack struct {
	stack.Stack
	mu                   sync.Mutex
	names, apps, targets []string
	fail                 bool
	readRequest          bool
}

type aliasTestConn struct{ net.Conn }

func (c aliasTestConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}
}

func (s *aliasTestStack) DialTCP(ctx context.Context, addr *net.TCPAddr) (net.Conn, error) {
	s.mu.Lock()
	name, _ := ctx.Value(resolve.ContextKeyResolveHost).(string)
	res, _ := ctx.Value(resolve.ContextKeyDomainResource).(client.DomainResource)
	s.names = append(s.names, name)
	s.apps = append(s.apps, res.AppID)
	s.targets = append(s.targets, addr.String())
	fail := s.fail
	readRequest := s.readRequest
	s.mu.Unlock()
	if fail {
		return nil, errors.New("test tunnel unavailable")
	}
	a, b := net.Pipe()
	go func() {
		defer b.Close()
		b.SetDeadline(time.Now().Add(time.Second))
		if readRequest {
			if _, err := b.Read(make([]byte, 32)); err != nil {
				return
			}
		}
		_, _ = io.WriteString(b, "vpn:"+name)
	}()
	return aliasTestConn{a}, nil
}

func aliasFixture(t *testing.T) (*captureAliases, *aliasTestStack) {
	t.Helper()
	s := &aliasTestStack{}
	domains := client.DomainResources{
		"a.corp.test": {{PortMin: 443, PortMax: 443, Protocol: "tcp", AppID: "app-a"}},
		"b.corp.test": {{PortMin: 8443, PortMax: 8443, Protocol: "tcp", AppID: "app-b"}},
	}
	r := resolve.NewResolver(s, "", "", 60, domains, nil, false)
	r.EnableSplitDNS([]string{"corp.test"})
	t.Cleanup(r.Close)
	ips := []client.IPResource{}
	return newCaptureAliases(r, ips, dial.NewDialer(s, r, ips, false, "")), s
}

func aliasAnswer(t *testing.T, a *captureAliases, name string) (string, []DNSAlias) {
	t.Helper()
	q := new(dns.Msg).SetQuestion(name+".", dns.TypeA)
	m := new(dns.Msg).SetReply(q)
	m.Answer = []dns.RR{
		&dns.CNAME{Hdr: dns.RR_Header{Name: name + ".", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 17}, Target: "shared.corp.test."},
		&dns.A{Hdr: dns.RR_Header{Name: "shared.corp.test.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 29}, A: net.ParseIP("10.90.0.9")},
	}
	got, aliases, err := a.answer(q, m, "198.19.64.0/20")
	if err != nil || got.Rcode != dns.RcodeSuccess || len(got.Answer) != 1 || len(aliases) != 1 {
		t.Fatalf("response=%v aliases=%v err=%v", got, aliases, err)
	}
	if got.Answer[0].Header().Name != name+"." || got.Answer[0].Header().Ttl != 17 {
		t.Fatal("shared canonical identity or TTL escaped")
	}
	if len(m.Answer) != 2 || m.Answer[1].(*dns.A).A.String() != "10.90.0.9" {
		t.Fatal("original diagnostic response changed")
	}
	return got.Answer[0].(*dns.A).A.String(), aliases
}

func TestCaptureAliasesKeepSharedIPAndCNAMEPermissionsSeparate(t *testing.T) {
	a, s := aliasFixture(t)
	one, records := aliasAnswer(t, a, "a.corp.test")
	two, _ := aliasAnswer(t, a, "b.corp.test")
	if one == two || records[0].Original != "10.90.0.9" || records[0].TTL != 17 {
		t.Fatal("shared real IP collapsed domain authority")
	}
	for _, tc := range []struct{ ip, port, want string }{{one, "443", "a.corp.test"}, {two, "8443", "b.corp.test"}} {
		conn, err := a.Dial(context.Background(), "tcp", net.JoinHostPort(tc.ip, tc.port))
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(conn)
		conn.Close()
		if err != nil || string(body) != "vpn:"+tc.want {
			t.Fatalf("wrong routing result %s %v", body, err)
		}
	}
	for _, addr := range []string{one + ":8443", two + ":443", one + ":80"} {
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		conn, err := a.Dial(ctx, "tcp", addr)
		cancel()
		if conn != nil {
			conn.Close()
			t.Fatal("ungranted port connected")
		}
		if !errors.Is(err, dial.ErrACLDenied) {
			t.Fatalf("ungranted port did not fail closed: %v", err)
		}
	}
	s.mu.Lock()
	if !reflect.DeepEqual(s.apps, []string{"app-a", "app-b"}) || !reflect.DeepEqual(s.targets, []string{"10.90.0.9:443", "10.90.0.9:8443"}) {
		t.Fatal("wrong resource reached tunnel")
	}
	s.fail = true
	s.mu.Unlock()
	if conn, err := a.Dial(context.Background(), "tcp", one+":443"); conn != nil || err == nil || !strings.Contains(err.Error(), "tunnel unavailable") {
		t.Fatal("tunnel failure did not propagate")
	}
}

func TestCaptureAliasExpiryNeverRetargetsAnotherName(t *testing.T) {
	a, _ := aliasFixture(t)
	now := time.Date(2026, 11, 20, 0, 0, 0, 0, time.UTC)
	a.now = func() time.Time { return now }
	one, _ := aliasAnswer(t, a, "a.corp.test")
	now = now.Add(18 * time.Second)
	if c, err := a.Dial(context.Background(), "tcp", one+":443"); c != nil || err == nil {
		t.Fatal("expired alias used")
	}
	two, _ := aliasAnswer(t, a, "b.corp.test")
	if one == two {
		t.Fatal("expired identity reused for another name")
	}
	renewed, _ := aliasAnswer(t, a, "a.corp.test")
	if renewed != one {
		t.Fatal("same domain/address identity should remain stable")
	}
	if c, err := a.Dial(context.Background(), "tcp", "198.19.64.1:443"); c != nil || err == nil {
		t.Fatal("unissued alias escaped")
	}
	if err := a.configure("198.19.80.0/20"); err == nil {
		t.Fatal("pool changed without new session")
	}
}

func TestCaptureAliasRefusesCoreResolverPool(t *testing.T) {
	a, _ := aliasFixture(t)
	if err := a.configure("198.18.16.0/20"); err == nil {
		t.Fatal("upstream resolver fake addresses could be interpreted as capture identities")
	}
	if err := a.configure("198.19.16.0/20"); err != nil {
		t.Fatal(err)
	}
}

func TestCaptureAliasPrivateSOCKSPreservesIdentity(t *testing.T) {
	a, _ := aliasFixture(t)
	one, _ := aliasAnswer(t, a, "a.corp.test")
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	password := strings.Repeat("x", 64)
	server := socks5.NewServer(socks5.WithAuthMethods([]socks5.Authenticator{socks5.UserPassAuthenticator{Credentials: socks5.StaticCredentials{"test": password}}}), socks5.WithResolver(a.resolver), socks5.WithRule(&socks5.PermitCommand{EnableConnect: true}), socks5.WithDial(a.Dial))
	done := make(chan error, 1)
	go func() { done <- server.Serve(ln) }()
	t.Cleanup(func() { ln.Close(); <-done })
	p, err := xproxy.SOCKS5("tcp", ln.Addr().String(), &xproxy.Auth{User: "test", Password: password}, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	conn, err := p.(xproxy.ContextDialer).DialContext(ctx, "tcp", one+":443")
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(conn)
	conn.Close()
	if err != nil || string(body) != "vpn:a.corp.test" {
		t.Fatal("SOCKS lost original domain", err)
	}
	if conn, err := p.(xproxy.ContextDialer).DialContext(ctx, "tcp", one+":8443"); err == nil {
		conn.Close()
		t.Fatal("SOCKS broadened port permission")
	}
}

func TestCaptureAliasFlattensCompleteExternalCNAMEWithoutPublicLookup(t *testing.T) {
	a, _ := aliasFixture(t)
	q := new(dns.Msg).SetQuestion("a.corp.test.", dns.TypeA)
	m := new(dns.Msg).SetReply(q)
	cname, _ := dns.NewRR("a.corp.test. 20 IN CNAME shared.vendor.example.")
	ip, _ := dns.NewRR("shared.vendor.example. 30 IN A 10.90.0.9")
	m.Answer = []dns.RR{cname, ip}
	got, aliases, err := a.answer(q, m, "198.19.64.0/20")
	if err != nil || got.Rcode != dns.RcodeSuccess || len(got.Answer) != 1 || got.Answer[0].Header().Name != "a.corp.test." || len(aliases) != 1 {
		t.Fatal("complete private chain not flattened", got, err)
	}
	m.Answer = m.Answer[:1]
	got, aliases, err = a.answer(q, m, "198.19.64.0/20")
	if err != nil || got.Rcode != dns.RcodeServerFailure || len(aliases) > 0 {
		t.Fatal("incomplete chain escaped to public resolver")
	}
}

func TestShorterRefreshDoesNotInvalidateStillCachedAlias(t *testing.T) {
	a, _ := aliasFixture(t)
	now := time.Date(2026, 11, 20, 0, 0, 0, 0, time.UTC)
	a.now = func() time.Time { return now }
	fake, _ := aliasAnswer(t, a, "a.corp.test") // advertised TTL 17
	now = now.Add(5 * time.Second)
	q := new(dns.Msg).SetQuestion("a.corp.test.", dns.TypeA)
	m := new(dns.Msg).SetReply(q)
	rr, _ := dns.NewRR("a.corp.test. 1 IN A 10.90.0.9")
	m.Answer = []dns.RR{rr}
	got, _, err := a.answer(q, m, "198.19.64.0/20")
	if err != nil || got.Answer[0].Header().Ttl != 1 {
		t.Fatal("refresh TTL changed")
	}
	now = now.Add(5 * time.Second)
	c, err := a.Dial(context.Background(), "tcp", fake+":443")
	if err != nil {
		t.Fatal("still-cacheable alias invalidated", err)
	}
	c.Close()
}
