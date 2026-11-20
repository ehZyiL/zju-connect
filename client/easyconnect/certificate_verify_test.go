package easyconnect

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestGatewayCertificateVerificationTruthTable(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	certDER := server.Certificate().Raw
	sum := sha256.Sum256(certDER)
	pin := hex.EncodeToString(sum[:])

	serverAddr := server.Listener.Addr().String()

	t.Run("untrusted cert without pin is rejected", func(t *testing.T) {
		client := NewClient(Options{
			Server: serverAddr,
		})
		defer client.Close()

		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+serverAddr, nil)
		_, err := client.httpClient.Do(req)
		if err == nil {
			t.Fatal("expected certificate verification failure for untrusted cert without pin, got nil")
		}
		lower := strings.ToLower(err.Error())
		if !strings.Contains(lower, "certificate") && !strings.Contains(lower, "x509") && !strings.Contains(lower, "tls") {
			t.Fatalf("unexpected error message: %v", err)
		}
	})

	t.Run("cert with correct pin is accepted", func(t *testing.T) {
		client := NewClient(Options{
			Server:            serverAddr,
			CertificateSHA256: pin,
		})
		defer client.Close()

		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+serverAddr, nil)
		resp, err := client.httpClient.Do(req)
		if err != nil {
			t.Fatalf("expected request to succeed with correct pin, got: %v", err)
		}
		_ = resp.Body.Close()
	})

	t.Run("cert with wrong pin is rejected", func(t *testing.T) {
		client := NewClient(Options{
			Server:            serverAddr,
			CertificateSHA256: strings.Repeat("0", 64),
		})
		defer client.Close()

		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+serverAddr, nil)
		_, err := client.httpClient.Do(req)
		if err == nil {
			t.Fatal("expected failure with wrong pin, got nil")
		}
		if !strings.Contains(err.Error(), "fingerprint") {
			t.Fatalf("expected fingerprint error, got: %v", err)
		}
	})
}
