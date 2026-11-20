package gvisor

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/mythologyli/zju-connect/client"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	gs "gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

type blackholeClient struct{ client.Client }

func (blackholeClient) CanUseTCPTunnel() bool { return false }

func TestUDPDialEmitsIPv4PacketForMappedInput(t *testing.T) {
	g := gs.New(gs.Options{NetworkProtocols: []gs.NetworkProtocolFactory{ipv4.NewProtocol}, TransportProtocols: []gs.TransportProtocolFactory{udp.NewProtocol}})
	defer g.Destroy()
	link := channel.New(16, 1500, "")
	defer link.Close()
	if err := g.CreateNIC(NICID, link); err != nil {
		t.Fatal(err)
	}
	source := tcpip.AddrFrom4([4]byte{10, 0, 0, 1})
	if err := g.AddProtocolAddress(NICID, tcpip.ProtocolAddress{Protocol: header.IPv4ProtocolNumber, AddressWithPrefix: tcpip.AddressWithPrefix{Address: source, PrefixLen: 24}}, gs.AddressProperties{}); err != nil {
		t.Fatal(err)
	}
	g.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: NICID}})
	s := &Stack{gvisorStack: g}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	dst := &net.UDPAddr{IP: net.ParseIP("10.0.0.2"), Port: 9000}
	conn, err := s.DialUDP(ctx, dst)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err = conn.Write([]byte("probe")); err != nil {
		t.Fatal(err)
	}
	packet := link.ReadContext(ctx)
	if packet == nil {
		t.Fatal("no IPv4 packet emitted")
	}
	defer packet.DecRef()
	view := packet.ToView()
	defer view.Release()
	ip := header.IPv4(view.AsSlice())
	if !ip.IsValid(view.Size()) || ip.DestinationAddress() != tcpip.AddrFrom4([4]byte{10, 0, 0, 2}) || ip.TransportProtocol() != udp.ProtocolNumber {
		t.Fatalf("wrong packet: %x", view.AsSlice())
	}
	udpHeader := header.UDP(ip.Payload())
	if udpHeader.DestinationPort() != 9000 || string(udpHeader.Payload()) != "probe" {
		t.Fatalf("wrong datagram: %x", ip.Payload())
	}
}

func TestTCPDialHonorsCancellation(t *testing.T) {
	g := gs.New(gs.Options{NetworkProtocols: []gs.NetworkProtocolFactory{ipv4.NewProtocol}, TransportProtocols: []gs.TransportProtocolFactory{tcp.NewProtocol}})
	defer g.Destroy()
	link := channel.New(16, 1500, "")
	defer link.Close()
	if err := g.CreateNIC(NICID, link); err != nil {
		t.Fatal(err)
	}
	if err := g.AddProtocolAddress(NICID, tcpip.ProtocolAddress{Protocol: header.IPv4ProtocolNumber, AddressWithPrefix: tcpip.AddressWithPrefix{Address: tcpip.AddrFrom4([4]byte{10, 0, 0, 1}), PrefixLen: 24}}, gs.AddressProperties{}); err != nil {
		t.Fatal(err)
	}
	g.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: NICID}})
	s := &Stack{gvisorStack: g, endpoint: &Endpoint{client: blackholeClient{}}}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		conn, err := s.DialTCP(ctx, &net.TCPAddr{IP: net.ParseIP("10.0.0.2"), Port: 53})
		if conn != nil {
			conn.Close()
		}
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("blackholed connection succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("L3 TCP connect ignored DNS cancellation")
	}
}
