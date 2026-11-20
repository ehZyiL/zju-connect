package pinnedcert

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"io"
	"math/big"
	"net"
	"testing"
	"time"
)

func TestProbeObservesOriginalCertificateWithoutApplicationData(t *testing.T) {
	for _, malformed := range []bool{false, true} {
		name := "normal"
		if malformed {
			name = "malformed SAN"
		}
		t.Run(name, func(t *testing.T) {
			key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "probe-test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
			if malformed {
				san, _ := asn1.Marshal([]asn1.RawValue{{Class: 2, Tag: 2, Bytes: []byte("内网.example")}})
				template.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 17}, Value: san}}
			}
			der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
			if err != nil {
				t.Fatal(err)
			}
			sum := sha256.Sum256(der)
			leaf, err := Parse(der, hex.EncodeToString(sum[:]))
			if err != nil {
				t.Fatal(err)
			}
			listener, err := net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			result := make(chan error, 1)
			go func() {
				raw, err := listener.Accept()
				if err != nil {
					result <- err
					return
				}
				defer raw.Close()
				_ = raw.SetDeadline(time.Now().Add(3 * time.Second))
				conn := tls.Server(raw, &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}}})
				if err := conn.Handshake(); err != nil {
					result <- err
					return
				}
				var one [1]byte
				if n, err := conn.Read(one[:]); n != 0 || err != io.EOF {
					result <- errors.New("probe sent application data or failed to close")
					return
				}
				result <- nil
			}()
			observed, err := Probe(context.Background(), listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(observed.Raw, der) || observed.Subject.CommonName != "probe-test" {
				t.Fatal("probe modified the certificate or returned another identity")
			}
			if err := <-result; err != nil {
				t.Fatal(err)
			}
			if malformed {
				if _, err := x509.ParseCertificate(der); err == nil {
					t.Fatal("probe weakened normal certificate parsing")
				}
			}
			if err := Match(der, hex.EncodeToString(make([]byte, 32))); err == nil {
				t.Fatal("observing certificate bypassed subsequent pin check")
			}
		})
	}
}

func TestProbeCancellationClosesHandshake(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	closed := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			closed <- err
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
		_, err = io.Copy(io.Discard, conn)
		closed <- err
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if _, err := Probe(ctx, listener.Addr().String()); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("probe ignored cancellation", err)
	}
	if err := <-closed; err != nil {
		t.Fatal("cancelled probe did not close its socket", err)
	}
}
