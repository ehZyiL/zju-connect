package desktop

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"
)

func TestCertificateProbeIPCNeedsNoCredentialsOrSession(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test-gateway"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		raw, err := listener.Accept()
		if err != nil {
			return
		}
		defer raw.Close()
		_ = raw.SetDeadline(time.Now().Add(2 * time.Second))
		conn := tls.Server(raw, &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}})
		_ = conn.Handshake()
	}()
	first := Message{Version: Version, Session: "probe-test", Type: "certificate_probe", Address: listener.Addr().String()}
	input, _ := json.Marshal(first)
	var output bytes.Buffer
	if code := Run(bytes.NewReader(input), &output); code != 0 {
		t.Fatalf("probe required login config or treated EOF as cancellation: %s", output.String())
	}
	<-done
	var reply Message
	if err := json.Unmarshal(output.Bytes(), &reply); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(der)
	if reply.Type != "certificate" || reply.Session != first.Session || reply.Address != first.Address || reply.Certificate == nil || reply.Certificate.SHA256 != hex.EncodeToString(sum[:]) || reply.Certificate.Subject != "CN=test-gateway" {
		t.Fatalf("wrong observation: %+v", reply)
	}
	if reply.Config != nil || reply.ChallengeID != "" || reply.Resources != nil {
		t.Fatal("probe started authentication or a VPN session")
	}
}

func TestCertificateProbeRejectsInvalidEndpointAndCleansLabels(t *testing.T) {
	input, _ := json.Marshal(Message{Version: Version, Session: "test", Type: "certificate_probe", Address: "https://user:password@gateway/path"})
	var output bytes.Buffer
	if code := Run(bytes.NewReader(input), &output); code == 0 {
		t.Fatal("invalid endpoint accepted")
	}
	var reply Message
	_ = json.Unmarshal(output.Bytes(), &reply)
	if reply.Type != "error" || strings.Contains(reply.Error, "password") {
		t.Fatal("invalid probe error")
	}
	label := certificateLabel("CN=test\n\u202e" + strings.Repeat("a", 1000))
	if strings.ContainsAny(label, "\n\u202e") || len([]rune(label)) > 257 {
		t.Fatal("peer-controlled label was not bounded/cleaned")
	}
}
