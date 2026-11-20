package desktop

import (
	"context"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/mythologyli/zju-connect/client"
	"github.com/mythologyli/zju-connect/dial"
	"github.com/mythologyli/zju-connect/resolve"
	"github.com/things-go/go-socks5"
	"github.com/things-go/go-socks5/statute"
)

type udpFixtureStack struct {
	aliasTestStack
	backend *net.UDPAddr
	dials   chan string
	closed  chan struct{}
}

func (s *udpFixtureStack) DialUDP(_ context.Context, target *net.UDPAddr) (net.Conn, error) {
	s.dials <- target.String()
	conn, err := net.DialUDP("udp4", nil, s.backend)
	if err != nil {
		return nil, err
	}
	return &udpFixtureConn{Conn: conn, closed: s.closed}, nil
}

type udpFixtureConn struct {
	net.Conn
	closed chan struct{}
}

func (c *udpFixtureConn) Close() error {
	err := c.Conn.Close()
	if err == nil {
		close(c.closed)
	}
	return err
}

func udpAssociate(t *testing.T, server *socks5.Server, endpoint *net.UDPAddr, password string) (net.Conn, *net.UDPAddr) {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		if c, err := ln.Accept(); err == nil {
			_ = server.ServeConn(c)
		}
	}()
	conn, err := net.DialTimeout("tcp4", ln.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	var reply [2]byte
	exchange := func(msg []byte) [2]byte {
		t.Helper()
		if _, err := conn.Write(msg); err != nil {
			t.Fatal(err)
		}
		if _, err := io.ReadFull(conn, reply[:]); err != nil {
			t.Fatal(err)
		}
		return reply
	}
	if got := exchange([]byte{5, 1, 2}); got != [2]byte{5, 2} {
		t.Fatalf("method reply: %v", got)
	}
	auth := append([]byte{1, 3, 'h', 'u', 'b', byte(len(password))}, password...)
	if got := exchange(auth); got != [2]byte{1, 0} {
		return conn, nil
	}
	request := statute.Request{Version: 5, Command: statute.CommandAssociate, DstAddr: statute.AddrSpec{AddrType: statute.ATYPIPv4, IP: endpoint.IP, Port: endpoint.Port}}
	if _, err := conn.Write(request.Bytes()); err != nil {
		t.Fatal(err)
	}
	bnd, err := statute.ParseReply(conn)
	if err != nil {
		t.Fatal(err)
	}
	if bnd.Response != statute.RepSuccess {
		return conn, nil
	}
	return conn, &net.UDPAddr{IP: bnd.BndAddr.IP, Port: bnd.BndAddr.Port}
}

func TestPrivateUDPAssociationStrictRouteAndLifetime(t *testing.T) {
	loop := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)}
	bind := func() *net.UDPConn {
		t.Helper()
		c, err := net.ListenUDP("udp4", loop)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = c.Close() })
		_ = c.SetDeadline(time.Now().Add(3 * time.Second))
		return c
	}
	backend := bind()
	app := bind()
	other := bind()
	s := &udpFixtureStack{backend: backend.LocalAddr().(*net.UDPAddr), dials: make(chan string, 8), closed: make(chan struct{})}
	resources := []client.IPResource{{IPMin: net.ParseIP("10.32.0.9"), IPMax: net.ParseIP("10.32.0.9"), PortMin: 9000, PortMax: 9001, Protocol: "udp"}}
	r := resolve.NewResolver(s, "", "", 60, client.DomainResources{"a.corp.test": {{PortMin: 9000, PortMax: 9000, Protocol: "udp"}}}, map[string][]net.IP{"a.corp.test": {net.ParseIP("10.32.0.9")}}, false)
	r.EnableSplitDNS([]string{"corp.test"})
	defer r.Close()
	a := newCaptureAliases(r, resources, dial.NewDialer(s, r, resources, false, ""))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c := &control{ctx: ctx}
	cfg := Config{SocksUser: "hub", SocksPassword: strings.Repeat("a", 64)}
	strict := newDesktopVPNOnlySOCKS(c, cfg, a, true)
	peer := app.LocalAddr().(*net.UDPAddr)
	for _, srv := range []*socks5.Server{newDesktopSOCKS(c, cfg, a), newDesktopVPNOnlySOCKS(c, cfg, a, false)} {
		if _, relay := udpAssociate(t, srv, peer, cfg.SocksPassword); relay != nil {
			t.Fatal("non-UDP listener granted an association")
		}
	}
	if _, relay := udpAssociate(t, strict, peer, "invalid-password"); relay != nil {
		t.Fatal("unauthenticated UDP association")
	}
	if _, relay := udpAssociate(t, strict, &net.UDPAddr{IP: peer.IP}, cfg.SocksPassword); relay != nil {
		t.Fatal("allowed wildcard UDP source port")
	}
	control, relay := udpAssociate(t, strict, peer, cfg.SocksPassword)
	if relay == nil || !relay.IP.IsLoopback() {
		t.Fatal("no private relay")
	}
	send := func(from *net.UDPConn, dest, msg string, frag byte) {
		t.Helper()
		packet, err := statute.NewDatagram(dest, []byte(msg))
		if err != nil {
			t.Fatal(err)
		}
		packet.Frag = frag
		if _, err := from.WriteToUDP(packet.Bytes(), relay); err != nil {
			t.Fatal(err)
		}
	}
	send(other, "10.32.0.9:9001", "foreign client", 0)
	send(app, "10.32.0.9:9001", "fragment", 1)
	send(app, "a.corp.test:9000", "first", 0)
	buf := make([]byte, 256)
	n, upstream, err := backend.ReadFromUDP(buf)
	if err != nil || string(buf[:n]) != "first" {
		t.Fatalf("upstream datagram = %q, %v", buf[:n], err)
	}
	if got := <-s.dials; got != "10.32.0.9:9000" {
		t.Fatalf("selected %s", got)
	}
	send(app, "10.32.0.9:9001", "retarget", 0)
	send(app, "a.corp.test:9000", "second", 0)
	n, _, err = backend.ReadFromUDP(buf)
	if err != nil || string(buf[:n]) != "second" {
		t.Fatalf("second datagram = %q, %v", buf[:n], err)
	}
	if _, err := backend.WriteToUDP([]byte("reply"), upstream); err != nil {
		t.Fatal(err)
	}
	n, _, err = app.ReadFromUDP(buf)
	if err != nil {
		t.Fatal(err)
	}
	packet, err := statute.ParseDatagram(buf[:n])
	if err != nil || packet.DstAddr.String() != "a.corp.test:9000" || string(packet.Data) != "reply" {
		t.Fatalf("relay reply = %+v, %v", packet, err)
	}
	_ = control.Close()
	select {
	case <-s.closed:
	case <-time.After(time.Second):
		t.Fatal("closed control connection left the tunnel UDP socket alive")
	}
	for _, target := range []string{"10.32.0.9:9999", "198.19.2.1:9000", "[::1]:9000"} {
		if conn, err := a.dialStrictVPNTarget(ctx, "udp", target); err == nil {
			_ = conn.Close()
			t.Fatalf("unauthorized target %s dialed", target)
		}
	}
	select {
	case target := <-s.dials:
		t.Fatalf("unexpected second tunnel dial %s", target)
	default:
	}
}
