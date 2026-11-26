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
		conn, err := s.endpoint.client.DialTCP(ctx, addr)
		if err == nil || !s.AllowTCPFallback || ctx.Err() != nil {
			return conn, err
		}
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
	ip := addr.IP.To4()
	if ip == nil {
		return nil, &net.AddrError{Err: "VPN UDP requires an IPv4 address", Addr: addr.String()}
	}
	conn, err := gonet.DialUDP(s.gvisorStack, nil, &tcpip.FullAddress{
		NIC:  NICID,
		Port: uint16(addr.Port),
		Addr: tcpip.AddrFromSlice(ip),
	}, header.IPv4ProtocolNumber)
	if err != nil {
		return nil, err
	}
	return conn, nil
}
