package ippool

import "testing"

func TestPoolExhaustionReturnsErrorWithoutReuse(t *testing.T) {
	p, err := NewIPPool[string]("198.18.0.0/30")
	if err != nil {
		t.Fatal(err)
	}
	ip, err := p.AllocateIP("first", "permission-a")
	if err != nil || ip.String() != "198.18.0.2" {
		t.Fatal(ip, err)
	}
	if _, err = p.AllocateIP("second", "permission-b"); err == nil {
		t.Fatal("exhausted pool reused or allocated broadcast address")
	}
	name, res, ok := p.GetDomain(ip)
	if !ok || name != "first" || res != "permission-a" {
		t.Fatal("existing permission replaced")
	}
	for _, cidr := range []string{"::/64", "0.0.0.0/0", "198.18.0.0/31"} {
		if _, err := NewIPPool[int](cidr); err == nil {
			t.Fatalf("invalid pool %s accepted", cidr)
		}
	}
}
