package atrust

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/mythologyli/zju-connect/client/atrust/auth"
	"net"
	"testing"
	"time"
)

func TestHubApplicationSnapshotAndFakeDestination(t *testing.T) {
	data := []byte(`{"data":{"appList":{"data":{"appInfo":[{"name":"Group","apps":[{"id":"first","accessModel":"L3VPN","addressList":[{"host":"one.corp","ip":["10.0.0.1"],"port":"443","protocol":"tcp"}]},{"id":"second","accessModel":"L3VPN","addressList":[{"host":"two.corp","ip":["10.0.0.1"],"port":"443","protocol":"tcp"}]}]}]}}}}`)
	c := &Client{}
	if err := c.parseResource(data); err != nil {
		t.Fatal(err)
	}
	apps := c.Apps()
	if len(apps) != 2 || apps[0].Name != "Group" {
		t.Fatalf("apps: %+v", apps)
	}
	apps[0].Addresses[0].Host = "changed"
	if c.Apps()[0].Addresses[0].Host != "one.corp" {
		t.Fatal("caller mutated internal resource")
	}
	c.ResourceData()[0] = 'x'
	if !json.Valid(c.ResourceData()) {
		t.Fatal("resource data aliases caller")
	}
	for _, domain := range []string{"one.corp", "two.corp"} {
		addr := c.realAddrForDomain(domain, &net.TCPAddr{IP: net.ParseIP("198.18.0.1"), Port: 443})
		if !addr.IP.Equal(net.ParseIP("10.0.0.1")) || addr.Port != 443 {
			t.Fatalf("mapped %s: %v", domain, addr)
		}
	}
}

func TestEmbeddedSessionInvalidReturnsWithoutExiting(t *testing.T) {
	if ProcessExitOnSessionInvalid {
		t.Fatal("embedded default exits process")
	}
	for _, payload := range []string{`{"code":10000004}`, `{"code":75500002}`} {
		if parseIPAuthResponse([]byte(payload)) == nil || parseTCPTunnelAuthResponse(payload) == nil {
			t.Fatal("accepted invalid session")
		}
	}
	c := NewClient(ClientOptions{Session: SessionOptions{SID: "old"}})
	defer c.Close()
	c.startSessionRefresh(func(context.Context) (auth.LoginResult, error) { return auth.LoginResult{}, auth.ErrSessionInvalid }, auth.ClientAuthData{}, nil, time.Millisecond)
	select {
	case <-c.refreshDone:
	case <-time.After(time.Second):
		t.Fatal("refresh did not finish")
	}
	if _, err := c.sessionSID(); !errors.Is(err, auth.ErrSessionInvalid) {
		t.Fatalf("session error: %v", err)
	}
}
