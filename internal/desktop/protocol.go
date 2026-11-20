// Package desktop is the private, versioned desktop worker interface.
// Keep protocol.go identical to aTrustHub/internal/workeripc/protocol.go.
package desktop

import (
	"encoding/binary"
	"errors"
	"net"
	"strconv"
)

const Version = 6
const MaxMessage = 2 << 20
const MaxDNSMessage = 65535
const MaxDNSRequests = 16
const MaxFlowRequests = 128

// StrictUDP is optional and advertised only for an IPv4 L3 VPN session.
const StrictUDP = "strict_udp_ready"

const MaxUDPPayload = 65507 - 262 // Maximum IPv4 UDP payload minus the largest SOCKS header.

// FlowResult reports a single TCP dial, not an HTTP/database operation. Route
// is the attempted path on failure. No upstream error text or credentials.
type FlowResult struct {
	Target      string `json:"target"`
	DialAddress string `json:"dialAddress,omitempty"`
	Route       string `json:"route"`
	Rule        string `json:"rule,omitempty"`
	Domain      string `json:"domain,omitempty"`
	IPMin       string `json:"ipMin,omitempty"`
	IPMax       string `json:"ipMax,omitempty"`
	Protocol    string `json:"protocol,omitempty"`
	PortMin     int    `json:"portMin,omitempty"`
	PortMax     int    `json:"portMax,omitempty"`
	Failure     string `json:"failure,omitempty"`
}

// The upstream resolver owns 198.18.0.0/16. Keep transparent capture identities
// separate even when both proxy modes run inside the same worker.
const CaptureAliasBlock = "198.19.0.0/16"

// ResourceSnapshot carries gateway permissions, not inferred address routes.
// It belongs to exactly one worker Session and is never persisted as authority.
type ResourceSnapshot struct {
	IPRules         []IPRule     `json:"ipRules,omitempty"`
	DomainRules     []DomainRule `json:"domainRules,omitempty"`
	StaticDNS       []DNSRecord  `json:"staticDNS,omitempty"`
	InternalDomains []string     `json:"internalDomains,omitempty"`
	DNSServer       string       `json:"dnsServer,omitempty"`
	Tunnel          string       `json:"tunnel"`
}

type IPRule struct {
	Min      string `json:"min"`
	Max      string `json:"max"`
	PortMin  int    `json:"portMin"`
	PortMax  int    `json:"portMax"`
	Protocol string `json:"protocol"`
}

type DomainRule struct {
	Domain   string `json:"domain"`
	PortMin  int    `json:"portMin"`
	PortMax  int    `json:"portMax"`
	Protocol string `json:"protocol"`
}

type DNSRecord struct {
	Name      string   `json:"name"`
	Addresses []string `json:"addresses"`
}

// DNSAlias is data for restoring an unselected application's original path;
// it never grants permission to enter the VPN. Install before releasing DNS.
type DNSAlias struct {
	Address  string `json:"address"`
	Original string `json:"original"`
	TTL      uint32 `json:"ttl"`
}

type Config struct {
	Server            string   `json:"server"`
	Username          string   `json:"username"`
	Password          string   `json:"password"`
	RemoteDNS         string   `json:"remoteDNS,omitempty"`
	InternalDomains   []string `json:"internalDomains,omitempty"`
	CertificateSHA256 string   `json:"certificateSHA256,omitempty"`
	SocksUser         string   `json:"socksUser"`
	SocksPassword     string   `json:"socksPassword"`
}

// CertificateInfo describes an observed gateway certificate, not a verified
// identity. certificate_probe is an optional, credential-free one-shot request;
// it leaves the v5 login/session protocol unchanged.
type CertificateInfo struct {
	SHA256       string `json:"sha256"`
	Subject      string `json:"subject"`
	Issuer       string `json:"issuer"`
	NotBefore    int64  `json:"notBefore"`
	NotAfter     int64  `json:"notAfter"`
	MalformedSAN bool   `json:"malformedSAN,omitempty"`
}

type Message struct {
	Version       int               `json:"version"`
	Session       string            `json:"session"`
	Type          string            `json:"type"`
	Config        *Config           `json:"config,omitempty"`
	ChallengeID   string            `json:"challengeId,omitempty"`
	Kind          string            `json:"kind,omitempty"`
	Image         []byte            `json:"image,omitempty"`
	Answer        string            `json:"answer,omitempty"`
	Address       string            `json:"address,omitempty"`
	VPNAddress    string            `json:"vpnAddress,omitempty"`
	Capabilities  []string          `json:"capabilities,omitempty"`
	ClientIP      string            `json:"clientIP,omitempty"`
	DNSServer     string            `json:"dnsServer,omitempty"`
	Error         string            `json:"error,omitempty"`
	RequestID     string            `json:"requestId,omitempty"`
	Deadline      int64             `json:"deadline,omitempty"` // Unix milliseconds; flow_prepare only
	DNS           []byte            `json:"dns,omitempty"`
	CaptureDNS    bool              `json:"captureDNS,omitempty"`
	CapturePrefix string            `json:"capturePrefix,omitempty"`
	DNSAliases    []DNSAlias        `json:"dnsAliases,omitempty"`
	Resources     *ResourceSnapshot `json:"resources,omitempty"`
	FlowReporting bool              `json:"flowReporting,omitempty"`
	Flow          *FlowResult       `json:"flow,omitempty"`
	Certificate   *CertificateInfo  `json:"certificate,omitempty"`
}

// DecodeUDPFrame accepts a complete, unfragmented IPv4/domain SOCKS datagram.
// Payload may be empty; it aliases the supplied packet until the next read.
func DecodeUDPFrame(packet []byte) (string, []byte, error) {
	invalid := func() (string, []byte, error) { return "", nil, errors.New("invalid private UDP datagram") }
	if len(packet) < 4 || packet[0] != 0 || packet[1] != 0 || packet[2] != 0 {
		return invalid()
	}
	var host string
	offset := 0
	switch packet[3] {
	case 1:
		if len(packet) < 10 {
			return invalid()
		}
		host, offset = net.IP(packet[4:8]).String(), 8
	case 3:
		if len(packet) < 5 || packet[4] == 0 || len(packet) < 7+int(packet[4]) {
			return invalid()
		}
		offset = 5 + int(packet[4])
		host = string(packet[5:offset])
	default:
		return invalid()
	}
	port := binary.BigEndian.Uint16(packet[offset : offset+2])
	if port == 0 || len(packet)-offset-2 > MaxUDPPayload {
		return invalid()
	}
	return net.JoinHostPort(host, strconv.Itoa(int(port))), packet[offset+2:], nil
}
