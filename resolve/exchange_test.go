package resolve

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/mythologyli/zju-connect/stack"
)

type dnsTestStack struct {
	stack.Stack
	address  string
	udp, tcp atomic.Int32
}

func (s *dnsTestStack) DialTCP(ctx context.Context, addr *net.TCPAddr) (net.Conn, error) {
	if !addr.IP.Equal(net.ParseIP("10.0.0.53")) || addr.Port != 53 {
		return nil, errors.New("unexpected DNS destination")
	}
	s.tcp.Add(1)
	return (&net.Dialer{}).DialContext(ctx, "tcp", s.address)
}
func (s *dnsTestStack) DialUDP(ctx context.Context, addr *net.UDPAddr) (net.Conn, error) {
	if !addr.IP.Equal(net.ParseIP("10.0.0.53")) || addr.Port != 53 {
		return nil, errors.New("unexpected DNS destination")
	}
	s.udp.Add(1)
	return (&net.Dialer{}).DialContext(ctx, "udp", s.address)
}

func TestInternalDNSWirePreservesCNAMEAndNegativeTTL(t *testing.T) {
	tcp, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	udp, err := net.ListenPacket("udp4", tcp.Addr().String())
	if err != nil {
		tcp.Close()
		t.Fatal(err)
	}
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, q *dns.Msg) {
		m := new(dns.Msg).SetReply(q)
		if w.RemoteAddr().Network() == "udp" {
			m.Truncated = true
		} else if strings.HasPrefix(q.Question[0].Name, "missing.") {
			m.Rcode = dns.RcodeNameError
			rr, _ := dns.NewRR("corp.test. 23 IN SOA ns.corp.test. admin.corp.test. 1 60 60 60 23")
			m.Ns = []dns.RR{rr}
		} else {
			cname, _ := dns.NewRR("app.corp.test. 47 IN CNAME target.corp.test.")
			ip, _ := dns.NewRR("target.corp.test. 31 IN A 10.1.2.3")
			m.Answer = []dns.RR{cname, ip}
		}
		_ = w.WriteMsg(m)
	})
	us := &dns.Server{PacketConn: udp, Handler: handler}
	ts := &dns.Server{Listener: tcp, Handler: handler}
	readyU, readyT := make(chan struct{}), make(chan struct{})
	us.NotifyStartedFunc = func() { close(readyU) }
	ts.NotifyStartedFunc = func() { close(readyT) }
	go us.ActivateAndServe()
	go ts.ActivateAndServe()
	defer us.Shutdown()
	defer ts.Shutdown()
	<-readyU
	<-readyT
	s := &dnsTestStack{address: tcp.Addr().String()}
	r := NewResolver(s, "10.0.0.53", "", 60, nil, nil, true)
	r.EnableSplitDNS([]string{"corp.test"})
	defer r.Close()
	q := new(dns.Msg).SetQuestion("app.corp.test.", dns.TypeA)
	m, err := r.ExchangeInternal(context.Background(), q)
	if err != nil || m.Rcode != dns.RcodeSuccess || len(m.Answer) != 2 {
		t.Fatalf("answer=%v err=%v", m, err)
	}
	if m.Answer[0].Header().Ttl != 47 || m.Answer[1].Header().Ttl != 31 || s.udp.Load() != 1 || s.tcp.Load() != 1 {
		t.Fatalf("records or fallback changed: %v", m)
	}
	q.SetQuestion("missing.corp.test.", dns.TypeAAAA)
	m, err = r.ExchangeInternal(context.Background(), q)
	if err != nil || m.Rcode != dns.RcodeNameError || len(m.Ns) != 1 || m.Ns[0].Header().Ttl != 23 {
		t.Fatalf("negative answer lost: %v %v", m, err)
	}
	if s.udp.Load() != 1 || s.tcp.Load() != 2 {
		t.Fatal("TCP fallback preference not retained")
	}
}

func TestInternalDNSRefusalStaticFailureAndCancellation(t *testing.T) {
	var calls atomic.Int32
	r := &Resolver{useRemoteDNS: true, dnsResource: map[string][]net.IP{"fixed.corp.test": {net.ParseIP("10.2.3.4")}}, wireExchange: func(context.Context, string, *dns.Msg) (*dns.Msg, error) {
		calls.Add(1)
		return nil, errors.New("private upstream details")
	}}
	r.EnableSplitDNS([]string{"corp.test"})
	defer r.Close()
	for _, tc := range []struct {
		name        string
		qtype       uint16
		code, count int
	}{
		{"public.example.", dns.TypeA, dns.RcodeRefused, 0},
		{"notcorp.test.", dns.TypeA, dns.RcodeRefused, 0},
		{"fixed.corp.test.", dns.TypeA, dns.RcodeSuccess, 1},
		{"fixed.corp.test.", dns.TypeAAAA, dns.RcodeSuccess, 0},
		{"missing.corp.test.", dns.TypeA, dns.RcodeServerFailure, 0},
		{"corp.test.", dns.TypeAXFR, dns.RcodeRefused, 0},
	} {
		t.Run(tc.name+dns.TypeToString[tc.qtype], func(t *testing.T) {
			q := new(dns.Msg).SetQuestion(tc.name, tc.qtype)
			m, err := r.ExchangeInternal(context.Background(), q)
			if err != nil || m.Rcode != tc.code || len(m.Answer) != tc.count {
				t.Fatalf("%v %v", m, err)
			}
		})
	}
	if calls.Load() != 2 {
		t.Fatalf("public/static query escaped to upstream: calls=%d", calls.Load())
	}
	r.wireExchange = func(ctx context.Context, _ string, _ *dns.Msg) (*dns.Msg, error) { <-ctx.Done(); return nil, ctx.Err() }
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := r.ExchangeInternal(ctx, new(dns.Msg).SetQuestion("slow.corp.test.", dns.TypeA)); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("cancellation: %v", err)
	}
	r.Close()
	if _, err := r.ExchangeInternal(context.Background(), new(dns.Msg).SetQuestion("corp.test.", dns.TypeA)); !errors.Is(err, net.ErrClosed) {
		t.Fatal("closed resolver accepted query")
	}
}

func TestInternalDNSRejectsMismatchedReplies(t *testing.T) {
	r := &Resolver{useRemoteDNS: true, wireExchange: func(_ context.Context, _ string, q *dns.Msg) (*dns.Msg, error) {
		m := new(dns.Msg).SetReply(q)
		m.Question[0].Name = "other.corp.test."
		return m, nil
	}}
	r.EnableSplitDNS([]string{"corp.test"})
	defer r.Close()
	m, err := r.ExchangeInternal(context.Background(), new(dns.Msg).SetQuestion("corp.test.", dns.TypeA))
	if err != nil || m.Rcode != dns.RcodeServerFailure {
		t.Fatalf("mismatched reply accepted: %v %v", m, err)
	}
}
