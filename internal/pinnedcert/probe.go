package pinnedcert

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"net"
	"strconv"
	"strings"
	"time"

	utls "github.com/refraction-networking/utls"
)

// Probe observes a certificate, not a trusted identity. This isolated connection
// sends only a TLS handshake: no HTTP request, credentials or client certificate.
// Its result must be explicitly approved before becoming an authentication pin.
func Probe(ctx context.Context, address string) (*x509.Certificate, error) {
	host, port, err := net.SplitHostPort(address)
	n, portErr := strconv.Atoi(port)
	if err != nil || host == "" || portErr != nil || n < 1 || n > 65535 || strings.ContainsAny(host, "/?#@\\ \t\r\n") {
		return nil, errors.New("invalid certificate probe address")
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	raw, err := (&net.Dialer{}).DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, err
	}
	defer raw.Close()
	config := &utls.Config{
		ServerName: host,
		// Diagnostic observation only. Login uses the separately saved pin.
		InsecureSkipVerify: true,
		ParsePeerCertificate: func(der []byte) (*x509.Certificate, error) {
			sum := sha256.Sum256(der)
			return Parse(der, hex.EncodeToString(sum[:]))
		},
	}
	conn := utls.UClient(raw, config, utls.HelloGolang)
	if err := conn.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	certificates := conn.ConnectionState().PeerCertificates
	if len(certificates) == 0 {
		return nil, errors.New("certificate probe returned no certificate")
	}
	return certificates[0], nil
}
