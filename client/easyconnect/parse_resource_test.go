package easyconnect

import (
	"net"
	"testing"

	"github.com/mythologyli/zju-connect/client"
)

func TestParseResourcesRetainsIPv6ForCaptureGuards(t *testing.T) {
	resource := `<Resource><Rcs>
		<Rc type="1" proto="0" host="2001:db8::7" port="443~443" />
		<Rc type="1" proto="1" host="2001:db8:1::/126" port="9000~9001" />
		<Rc type="1" proto="0" host="https://[fd00::a]:9443/path" port="443~443" />
		<Rc type="1" proto="0" host="fd00::10~fd00::1f" port="443~443" />
		<Rc type="1" proto="0" host="192.0.2.5:8443" port="443~443" />
	</Rcs><Dns data="1:only-v6.example:fd00::20;1:mixed.example:192.0.2.6" dnsserver="192.0.2.53" /></Resource>`
	c := &Client{useDomainResource: true}
	if err := c.parseResources(resource); err != nil {
		t.Fatal(err)
	}
	want := []struct {
		lo, hi, network string
		first, last     int
	}{
		{"2001:db8::7", "2001:db8::7", "tcp", 443, 443},
		{"2001:db8:1::", "2001:db8:1::3", "udp", 9000, 9001},
		{"fd00::a", "fd00::a", "tcp", 9443, 9443},
		{"fd00::10", "fd00::1f", "tcp", 443, 443},
		{"192.0.2.5", "192.0.2.5", "tcp", 8443, 8443},
	}
	if len(c.ipResources) != len(want) || len(c.domainResources) != 0 {
		t.Fatalf("address rules = %+v; domain rules = %+v", c.ipResources, c.domainResources)
	}
	for i, rule := range c.ipResources {
		w := want[i]
		if rule.IPMin.String() != w.lo || rule.IPMax.String() != w.hi || rule.Protocol != w.network || rule.PortMin != w.first || rule.PortMax != w.last {
			t.Errorf("rule %d = %+v; want %+v", i, rule, w)
		}
	}
	if prefixes := c.ipSet.Prefixes(); len(prefixes) != 1 || prefixes[0].String() != "192.0.2.5/32" {
		t.Fatalf("CLI route prefixes = %v; want only the IPv4 resource", prefixes)
	}
	for name, want := range map[string]net.IP{"only-v6.example": net.ParseIP("fd00::20"), "mixed.example": net.ParseIP("192.0.2.6")} {
		got := c.dnsResource[name]
		if len(got) != 1 || !got[0].Equal(want) {
			t.Errorf("static DNS %s = %v; want %v", name, got, want)
		}
	}
}

func TestParseResourcesPreservesMultipleRulesForDomain(t *testing.T) {
	resource := `<Resource><Rcs>
		<Rc type="1" proto="0" host="www.cnki.net" port="443~443" />
		<Rc type="1" proto="0" host="www.cnki.net" port="80~80" />
	</Rcs><Dns data="" dnsserver="10.0.0.1" /></Resource>`
	c := &Client{useDomainResource: true}
	if err := c.parseResources(resource); err != nil {
		t.Fatalf("parseResources() error = %v", err)
	}

	rules := c.domainResources["www.cnki.net"]
	if len(rules) != 2 {
		t.Fatalf("domain rules = %#v, want 2 rules", rules)
	}
	for _, port := range []int{80, 443} {
		if _, ok := client.MatchDomainResource(rules, "tcp", port); !ok {
			t.Fatalf("domain rules did not match tcp/%d: %#v", port, rules)
		}
	}
}
