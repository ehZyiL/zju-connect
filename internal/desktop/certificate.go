package desktop

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"unicode"

	"github.com/mythologyli/zju-connect/internal/pinnedcert"
)

// This branch never constructs an EasyConnect client or reads saved credentials.
// Its input is one endpoint. EOF is normal, and the probe has its own timeout.
func probeCertificate(first Message, output io.Writer) int {
	reply := Message{Version: Version, Session: first.Session, Type: "certificate", Address: first.Address}
	cert, err := pinnedcert.Probe(context.Background(), first.Address)
	if err != nil {
		reply.Type = "error"
		reply.Error = "无法读取网关证书，请检查地址和网络后重试"
		if errors.Is(err, context.DeadlineExceeded) {
			reply.Error = "读取网关证书超时，请检查网络后重试"
		}
	} else {
		sum := sha256.Sum256(cert.Raw)
		_, parseErr := x509.ParseCertificate(cert.Raw)
		reply.Certificate = &CertificateInfo{
			SHA256: hex.EncodeToString(sum[:]), Subject: certificateLabel(cert.Subject.String()), Issuer: certificateLabel(cert.Issuer.String()),
			NotBefore: cert.NotBefore.Unix(), NotAfter: cert.NotAfter.Unix(),
			MalformedSAN: parseErr != nil && strings.Contains(parseErr.Error(), "SAN dNSName is malformed"),
		}
	}
	if json.NewEncoder(output).Encode(reply) != nil || err != nil {
		return 1
	}
	return 0
}

// Certificate labels are peer-controlled display data, never trusted UI text.
func certificateLabel(value string) string {
	value = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.In(r, unicode.Cf) {
			return ' '
		}
		return r
	}, value)
	runes := []rune(value)
	if len(runes) > 256 {
		return string(runes[:256]) + "…"
	}
	return value
}
