package desktop

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"net"
	"os"
	"testing"

	"github.com/mythologyli/zju-connect/client"
	"github.com/mythologyli/zju-connect/dial"
	"github.com/mythologyli/zju-connect/resolve"
)

// TestAliasPlatformPeer exposes the real desktop DNS IPC and SOCKS adapter to
// the Linux namespace test. Only the remote VPN stack is a fixture; no gateway
// credentials or remote network calls exist in this test path.
func TestAliasPlatformPeer(t *testing.T) {
	if os.Getenv("ECH_ALIAS_PEER") != "1" {
		t.Skip("namespace fixture subprocess only")
	}
	self, _ := os.Readlink("/proc/self/ns/net")
	if host := os.Getenv("EASYCONNECT_CAPTURE_HOST_NETNS"); host == "" || host == self {
		os.Exit(2)
	}
	log.SetOutput(io.Discard)
	var setup struct {
		Original     string
		PortA, PortB int
		Password     string
	}
	dec, enc := json.NewDecoder(os.Stdin), json.NewEncoder(os.Stdout)
	if dec.Decode(&setup) != nil || net.ParseIP(setup.Original).To4() == nil || setup.PortA < 1 || setup.PortB < 1 {
		os.Exit(2)
	}
	s := &aliasTestStack{readRequest: true}
	domains := client.DomainResources{"a.corp.test": {{PortMin: setup.PortA, PortMax: setup.PortA, Protocol: "tcp", AppID: "a"}}, "b.corp.test": {{PortMin: setup.PortB, PortMax: setup.PortB, Protocol: "tcp", AppID: "b"}}}
	records := map[string][]net.IP{"a.corp.test": {net.ParseIP(setup.Original)}, "b.corp.test": {net.ParseIP(setup.Original)}}
	r := resolve.NewResolver(s, "", "", 60, domains, records, false)
	r.EnableSplitDNS([]string{"corp.test"})
	ips := []client.IPResource{}
	aliases := newCaptureAliases(r, ips, dial.NewDialer(s, r, ips, false, ""))
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		os.Exit(2)
	}
	ctx, cancel := context.WithCancel(context.Background())
	c := &control{ctx: ctx, cancel: cancel, session: "alias-fixture", encoder: enc}
	server := newDesktopSOCKS(c, Config{SocksUser: "test", SocksPassword: setup.Password}, aliases)
	go server.Serve(ln)
	c.setDNSHandler(dnsHandler(r, ips, aliases))
	if c.emit(Message{Type: "ready", Address: ln.Addr().String()}) != nil {
		os.Exit(2)
	}
	for {
		var m Message
		if dec.Decode(&m) != nil || !c.accept(m) {
			break
		}
	}
	cancel()
	c.stopDNS()
	r.Close()
	ln.Close()
	os.Exit(0)
}
