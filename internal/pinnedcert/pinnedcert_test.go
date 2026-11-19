package pinnedcert

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"
)

func TestPinnedMalformedSAN(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	san, _ := asn1.Marshal([]asn1.RawValue{{Class: 2, Tag: 2, Bytes: []byte("内网.example")}})
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "legacy"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment, ExtraExtensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 17}, Value: san}}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(der)
	pin := hex.EncodeToString(sum[:])
	if _, err := x509.ParseCertificate(der); err == nil {
		t.Fatal("fixture must fail standard parsing")
	}
	cert, err := Parse(der, pin)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(cert.Raw, der) {
		t.Fatal("original certificate DER changed")
	}
	if err := cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature); err != nil {
		t.Fatalf("original signature no longer verifies: %v", err)
	}
	if _, err := Parse(der, strings.Repeat("0", 64)); err == nil {
		t.Fatal("wrong pin accepted")
	}
	if _, err := Parse(append(der, 0), pin); err == nil {
		t.Fatal("changed DER accepted")
	}
	if err := Verify(pin)([][]byte{der}, nil); err != nil {
		t.Fatal(err)
	}
	if err := Verify(strings.Repeat("0", 64))([][]byte{der}, nil); err == nil {
		t.Fatal("leaf pin not enforced")
	}

	base := &utls.Config{InsecureSkipVerify: true, VerifyPeerCertificate: Verify(pin), ParsePeerCertificate: func(raw []byte) (*x509.Certificate, error) { return Parse(raw, pin) }}
	for _, tc := range []struct {
		name    string
		config  *utls.Config
		success bool
	}{
		{"pinned clone", base.Clone(), true},
		{"strict after relaxed", &utls.Config{InsecureSkipVerify: true}, false},
		{"wrong pin", &utls.Config{InsecureSkipVerify: true, VerifyPeerCertificate: Verify(strings.Repeat("0", 64)), ParsePeerCertificate: base.ParsePeerCertificate}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			left, right := net.Pipe()
			defer left.Close()
			defer right.Close()
			_ = left.SetDeadline(time.Now().Add(3 * time.Second))
			_ = right.SetDeadline(time.Now().Add(3 * time.Second))
			server := tls.Server(left, &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key, Leaf: cert}}})
			done := make(chan struct{})
			go func() { _ = server.Handshake(); _ = left.Close(); close(done) }()
			conn := utls.UClient(right, tc.config, utls.HelloGolang)
			err := conn.Handshake()
			_ = right.Close()
			<-done
			if (err == nil) != tc.success {
				t.Fatalf("handshake success=%v, error=%v", tc.success, err)
			}
		})
	}
}
