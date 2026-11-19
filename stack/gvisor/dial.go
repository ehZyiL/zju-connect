package gvisor

import (
	"context"
	"net"

	"github.com/mythologyli/zju-connect/resolve"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

func (s *Stack) DialTCP(ctx context.Context, addr *net.TCPAddr) (net.Conn, error) {
	if s.endpoint.client.CanUseTCPTunnel() && !resolve.TCPPrefersL3(ctx) {
		return s.endpoint.client.DialTCP(ctx, addr)
	}

	conn, err := gonet.DialContextTCP(ctx, s.gvisorStack, tcpip.FullAddress{
		NIC:  NICID,
		Port: uint16(addr.Port),
		Addr: tcpip.AddrFromSlice(addr.IP),
	}, header.IPv4ProtocolNumber)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

func (s *Stack) DialUDP(ctx context.Context, addr *net.UDPAddr) (net.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	conn, err := gonet.DialUDP(s.gvisorStack, nil, &tcpip.FullAddress{
		NIC:  NICID,
		Port: uint16(addr.Port),
		Addr: tcpip.AddrFromSlice(addr.IP),
	}, header.IPv4ProtocolNumber)
	if err != nil {
		return nil, err
	}
	return conn, nil
}
