package atrust

import "net"

// realAddrForDomain maps a fake address back to the address the server gave
// for that domain. Anything else is returned untouched.
func (c *Client) realAddrForDomain(domain string, addr *net.TCPAddr) *net.TCPAddr {
	if c.dnsResource == nil {
		return addr
	}
	ips, ok := c.dnsResource[domain]
	if !ok || len(ips) == 0 {
		return addr
	}
	for _, ip := range ips {
		if ip.Equal(addr.IP) {
			return addr
		}
	}
	return &net.TCPAddr{IP: ips[0], Port: addr.Port}
}
