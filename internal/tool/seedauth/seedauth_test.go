package seedauth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/internal/tool"
)

// A provided cookie is passed straight through as the captured session —
// no network call. This is the common case (webappsec already holds a
// session from the user's browser).
func TestSeedAuth_ProvidedCookiePassthrough(t *testing.T) {
	res, err := New().Run(context.Background(), tool.Args{"cookie": "session=abc123"})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.CapturedSession != "session=abc123" {
		t.Fatalf("CapturedSession = %q, want passthrough %q", res.CapturedSession, "session=abc123")
	}
}

// With neither a cookie nor a login_url there's nothing to do — that's a
// caller error, not a silent no-op.
func TestSeedAuth_MissingInputsErrors(t *testing.T) {
	_, err := New().Run(context.Background(), tool.Args{})
	if err == nil {
		t.Fatal("expected error when neither cookie nor login_url is set")
	}
}

// Form login: POST credentials, capture the Set-Cookie from the (302)
// response. The handler emulates a typical login that sets a session
// cookie and redirects.
func TestSeedAuth_FormLoginCapturesCookie(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Errorf("ParseForm: %v", err)
		}
		if got := r.Form.Get("username"); got != "alice" {
			t.Errorf("username field = %q, want alice", got)
		}
		if got := r.Form.Get("password"); got != "s3cret" {
			t.Errorf("password field = %q, want s3cret", got)
		}
		http.SetCookie(w, &http.Cookie{Name: "session", Value: "tok-xyz"})
		w.WriteHeader(http.StatusFound) // 302 — cookie rides the redirect
	}))
	defer srv.Close()

	res, err := New().Run(context.Background(), tool.Args{
		"login_url": srv.URL,
		"username":  "alice",
		"password":  "s3cret",
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !strings.Contains(res.CapturedSession, "session=tok-xyz") {
		t.Fatalf("CapturedSession = %q, want it to contain session=tok-xyz", res.CapturedSession)
	}
}

// Custom field names route through to the form body.
func TestSeedAuth_CustomFieldNames(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.Form.Get("email") != "a@b.com" || r.Form.Get("pass") != "pw" {
			t.Errorf("custom fields not honored: %v", r.Form)
		}
		http.SetCookie(w, &http.Cookie{Name: "sid", Value: "1"})
	}))
	defer srv.Close()

	res, err := New().Run(context.Background(), tool.Args{
		"login_url":      srv.URL,
		"username":       "a@b.com",
		"password":       "pw",
		"username_field": "email",
		"password_field": "pass",
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !strings.Contains(res.CapturedSession, "sid=1") {
		t.Fatalf("CapturedSession = %q, want sid=1", res.CapturedSession)
	}
}

// Auth failure (no Set-Cookie) must NOT crash the scan: seed_auth returns
// a result with no session, and downstream tools then scan
// unauthenticated. This is the graceful-degradation contract.
func TestSeedAuth_FailureDoesNotError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK) // no Set-Cookie
	}))
	defer srv.Close()

	res, err := New().Run(context.Background(), tool.Args{"login_url": srv.URL})
	if err != nil {
		t.Fatalf("auth failure should be swallowed, got err: %v", err)
	}
	if res.CapturedSession != "" {
		t.Fatalf("expected no session on failure, got %q", res.CapturedSession)
	}
}

func TestSeedAuth_Identity(t *testing.T) {
	s := New()
	if s.Name() != "seed_auth" {
		t.Errorf("Name = %q, want seed_auth", s.Name())
	}
	if !s.SandboxExecution() {
		t.Error("SandboxExecution should be true")
	}
	if _, ok := tool.Get("seed_auth"); !ok {
		t.Error("seed_auth not registered")
	}
}
