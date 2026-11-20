package desktop

import (
	"context"
	"io"
	"net"
	"time"

	"github.com/things-go/go-socks5"
	"github.com/things-go/go-socks5/statute"
)

const (
	maxUDPAssociations = 128
	udpIdle            = 60 * time.Second
)

// Each private association is pinned to one local UDP socket and one VPN
// destination. Ordinary SOCKS never exposes ASSOCIATE or this relay.
func serveStrictUDP(ctx context.Context, writer io.Writer, req *socks5.Request, slots chan struct{}, dial func(context.Context, string, string) (net.Conn, error)) error {
	peer, ok := req.RemoteAddr.(*net.TCPAddr)
	if !ok || peer.IP.To4() == nil || !peer.IP.IsLoopback() || req.DestAddr.AddrType != statute.ATYPIPv4 || !req.DestAddr.IP.Equal(peer.IP) || req.DestAddr.Port == 0 {
		return socks5.SendReply(writer, statute.RepRuleFailure, nil)
	}
	select {
	case slots <- struct{}{}:
		defer func() { <-slots }()
	default:
		return socks5.SendReply(writer, statute.RepServerFailure, nil)
	}
	controlConn, ok := writer.(net.Conn)
	if !ok {
		return socks5.SendReply(writer, statute.RepServerFailure, nil)
	}
	// The OS rejects stray packets from any other source IP or port.
	relay, err := net.DialUDP("udp4", &net.UDPAddr{IP: peer.IP}, &net.UDPAddr{IP: peer.IP, Port: req.DestAddr.Port})
	if err != nil {
		return socks5.SendReply(writer, statute.RepServerFailure, nil)
	}
	defer relay.Close()
	life, cancel := context.WithCancel(ctx)
	defer cancel()
	closeRelay := context.AfterFunc(life, func() { _ = relay.Close(); _ = controlConn.Close() })
	defer closeRelay()
	if err := socks5.SendReply(writer, statute.RepSuccess, relay.LocalAddr()); err != nil {
		return err
	}
	controlDone := make(chan struct{})
	go func() {
		defer close(controlDone)
		// No more commands belong on a successful association's TCP stream.
		var b [1]byte
		_, _ = req.Reader.Read(b[:])
		cancel()
	}()
	defer func() { _ = controlConn.Close(); <-controlDone }()

	buffer := make([]byte, 65535)
	_ = relay.SetReadDeadline(time.Now().Add(udpIdle))
	first, err := readStrictDatagram(relay, buffer, "")
	if err != nil {
		return err
	}
	target := first.DstAddr.String()
	// The private protocol opens a target with a single marker byte; never
	// send that marker to the business service. Normal packets follow ready.
	if len(first.Data) != 1 || first.Data[0] != 0 {
		return io.ErrUnexpectedEOF
	}
	dialCtx, finish := context.WithTimeout(life, 10*time.Second)
	upstream, err := dial(dialCtx, "udp", target)
	finish()
	if err != nil {
		return err
	}
	defer upstream.Close()
	if life.Err() != nil {
		return life.Err()
	}
	closeUpstream := context.AfterFunc(life, func() { _ = upstream.Close() })
	defer closeUpstream()

	refresh := func() {
		until := time.Now().Add(udpIdle)
		_ = relay.SetDeadline(until)
		_ = upstream.SetDeadline(until)
	}
	refresh()
	if _, err := writer.Write([]byte{0}); err != nil {
		return err
	}
	responseDone := make(chan struct{})
	header := first.Header()
	go func() {
		defer close(responseDone)
		defer cancel()
		// Keep the reply header and payload together; one Write is one packet.
		out := make([]byte, len(header)+65535)
		copy(out, header)
		for {
			n, err := upstream.Read(out[len(header):])
			if err != nil {
				return
			}
			if n > MaxUDPPayload {
				continue
			}
			refresh()
			if _, err := relay.Write(out[:len(header)+n]); err != nil {
				return
			}
		}
	}()
	defer func() { cancel(); _ = upstream.Close(); _ = relay.Close(); <-responseDone }()
	for {
		packet, err := readStrictDatagram(relay, buffer, target)
		if err != nil {
			return err
		}
		refresh()
		if _, err := upstream.Write(packet.Data); err != nil {
			return err
		}
	}
}

func readStrictDatagram(relay *net.UDPConn, buffer []byte, target string) (statute.Datagram, error) {
	for {
		n, err := relay.Read(buffer)
		if err != nil {
			return statute.Datagram{}, err
		}
		if n < 4 || buffer[0] != 0 || buffer[1] != 0 || buffer[2] != 0 {
			continue
		}
		address, data, err := DecodeUDPFrame(buffer[:n])
		if err != nil {
			continue
		}
		if target != "" && address != target {
			continue
		}
		packet, err := statute.NewDatagram(address, data)
		if err != nil {
			continue
		}
		return packet, nil
	}
}
