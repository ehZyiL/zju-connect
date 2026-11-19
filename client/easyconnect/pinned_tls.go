package easyconnect

import (
	"context"
	"crypto/x509"
	"net"
	"net/http"
	"strings"

	"github.com/mythologyli/zju-connect/internal/pinnedcert"
	utls "github.com/refraction-networking/utls"
)

func (c *Client) tunnelTLSConfig() *utls.Config {
	config := &utls.Config{InsecureSkipVerify: true, KeyLogWriter: c.tlsKeyLogWriter}
	if c.certificateSHA256 != "" {
		pin := c.certificateSHA256
		config.VerifyPeerCertificate = pinnedcert.Verify(pin)
		config.ParsePeerCertificate = func(der []byte) (*x509.Certificate, error) { return pinnedcert.Parse(der, pin) }
	}
	return config
}

func (c *Client) configurePinnedHTTP(transport *http.Transport) {
	if c.certificateSHA256 == "" {
		return
	}
	transport.Proxy = nil
	transport.ForceAttemptHTTP2 = false
	transport.DialTLSContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		raw, err := c.dialContext(ctx, network, address)
		if err != nil {
			return nil, err
		}
		config := c.tunnelTLSConfig()
		config.ServerName, _, _ = net.SplitHostPort(address)
		config.ServerName = strings.Trim(config.ServerName, "[]")
		config.NextProtos = []string{"http/1.1"}
		config.Renegotiation = utls.RenegotiationSupport(transport.TLSClientConfig.Renegotiation)
		for _, cert := range transport.TLSClientConfig.Certificates {
			config.Certificates = append(config.Certificates, utls.Certificate{
				Certificate: cert.Certificate, PrivateKey: cert.PrivateKey, Leaf: cert.Leaf,
				OCSPStaple: cert.OCSPStaple, SignedCertificateTimestamps: cert.SignedCertificateTimestamps,
			})
		}
		conn := utls.UClient(raw, config, utls.HelloGolang)
		if err := conn.HandshakeContext(ctx); err != nil {
			_ = raw.Close()
			return nil, err
		}
		return conn, nil
	}
}
