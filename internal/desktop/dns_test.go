package desktop

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/miekg/dns"
	"io"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestDNSControlBoundsCancellationAndStop(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r, w := io.Pipe()
	defer r.Close()
	defer w.Close()
	c := &control{ctx: ctx, cancel: cancel, session: "test", encoder: json.NewEncoder(w)}
	started := make(chan struct{}, MaxDNSRequests)
	c.setDNSHandler(func(ctx context.Context, _ []byte, _ bool, _ string) (dnsReply, error) {
		started <- struct{}{}
		<-ctx.Done()
		return dnsReply{}, errors.New("secret DNS details")
	})
	q, _ := new(dns.Msg).SetQuestion("corp.test.", dns.TypeA).Pack()
	for i := 1; i <= MaxDNSRequests; i++ {
		if !c.accept(Message{Version: Version, Session: "test", Type: "dns_query", RequestID: strconv.Itoa(i), DNS: q}) {
			t.Fatal("query rejected")
		}
		<-started
	}
	overflow := make(chan bool, 1)
	go func() {
		overflow <- c.accept(Message{Version: Version, Session: "test", Type: "dns_query", RequestID: "17", DNS: q})
	}()
	dec := json.NewDecoder(r)
	var m Message
	if err := dec.Decode(&m); err != nil {
		t.Fatal(err)
	}
	if m.RequestID != "17" || m.Error == "" || !<-overflow {
		t.Fatalf("overflow not rejected: %+v", m)
	}
	if !c.accept(Message{Version: Version, Session: "test", Type: "dns_cancel", RequestID: "1"}) {
		t.Fatal("cancel rejected")
	}
	if err := dec.Decode(&m); err != nil {
		t.Fatal(err)
	}
	if m.RequestID != "1" || m.Error == "" || strings.Contains(m.Error, "secret") {
		t.Fatal("cancel response not sanitized")
	}
	// Session stop cancels all in-flight work without blocking on unread output.
	cancel()
	done := make(chan struct{})
	go func() { c.stopDNS(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("DNS workers did not stop")
	}
}
