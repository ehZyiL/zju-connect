package auth

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

func TestQyWechatUsesSessionCookiesAndRelativeRedirects(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/passport/v1/auth/qywechat":
			if r.Header.Get("x-csrf-token") != "csrf" {
				t.Error("missing CSRF token")
			}
			http.SetCookie(w, &http.Cookie{Name: "sid", Value: "session", Path: "/"})
			http.Redirect(w, r, "/qrcode_middle.html", http.StatusFound)
		case "/qrcode_middle.html":
			cookie, err := r.Cookie("sid")
			if err != nil || cookie.Value != "session" {
				t.Error("callback cookies lost")
			}
			http.Redirect(w, r, "/portal/shortcut.html?data="+url.QueryEscape(`{"ticket":"portal"}`), http.StatusFound)
		default:
			t.Errorf("unexpected request: %s", r.URL.Path)
		}
	}))
	defer srv.Close()
	s := newTLSTestSession(srv)
	s.csrfToken = "csrf"
	if err := s.qywechat(srv.URL + "/passport/v1/auth/qywechat?code=authorization"); err != nil {
		t.Fatal(err)
	}
	if s.ticket != "portal" {
		t.Fatalf("ticket = %q", s.ticket)
	}
	if snap, err := s.Snapshot(); err != nil || snap.SID != "session" {
		t.Fatalf("snapshot = %+v, %v", snap, err)
	}
}

func TestQyWechatRejectsForeignCallbacksAndRedirects(t *testing.T) {
	s := NewSession("gateway.test:8443", nil)
	for _, raw := range []string{"http://gateway.test:8443/callback", "https://other.test/callback", "https://gateway.test/callback", "https://user@gateway.test:8443/callback"} {
		if _, err := s.qywechatURL(raw); err == nil {
			t.Errorf("accepted %q", raw)
		}
	}
	if _, err := s.qywechatURL("/qrcode_middle.html"); err != nil {
		t.Fatal(err)
	}
}

func TestPortalTicketAndOnlineProbe(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/passport/v1/public/authConfig" {
			io.WriteString(w, `{"code":0,"data":{"isLogin":1,"portalTicket":"portal","antiMITMAttackData":{}}}`)
		} else {
			io.WriteString(w, `{"code":75500002,"message":"session replaced","data":{}}`)
		}
	}))
	defer srv.Close()
	s := newTLSTestSession(srv)
	if _, _, err := s.authConfig(false, true); err != nil {
		t.Fatal(err)
	}
	if s.ticket != "portal" {
		t.Fatalf("ticket = %q", s.ticket)
	}
	_, code, message, err := s.OnlineProbe()
	if err != nil || code != 75500002 || message != "session replaced" {
		t.Fatalf("probe: %d %q %v", code, message, err)
	}
}

func TestRefreshOutlivesSetupAndHonorsOwnerCancellation(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "sid", Value: "refreshed", Path: "/"})
		io.WriteString(w, `{"code":0,"data":{"isLogin":1}}`)
	}))
	defer srv.Close()
	setup, cancelSetup := context.WithCancel(context.Background())
	s := newTLSTestSession(srv).WithContext(setup)
	owner, cancelOwner := context.WithCancel(context.Background())
	defer cancelOwner()
	refresh := s.WithContext(owner)
	cancelSetup()
	snap, err := refresh.Refresh(owner)
	if err != nil || snap.SID != "refreshed" {
		t.Fatalf("refresh after setup: %+v %v", snap, err)
	}
	cancelOwner()
	if _, err := refresh.Refresh(owner); !errors.Is(err, context.Canceled) {
		t.Fatalf("refresh after close: %v", err)
	}
}

func TestBrowserCaptchaHonorsCancelledLogin(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := serveCaptchaInBrowser(ctx, nil, time.Minute); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}
