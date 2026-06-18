package connector

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestGitHub_VerifyWebhook(t *testing.T) {
	g := NewGitHub("a", "b")
	body := []byte(`{"repository":{"html_url":"https://github.com/acme/web"}}`)
	secret := "shh"
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	sig := "sha256=" + hex.EncodeToString(mac.Sum(nil))

	h := http.Header{}
	h.Set("X-Hub-Signature-256", sig)
	if err := g.VerifyWebhook(h, body, secret); err != nil {
		t.Fatalf("a valid HMAC should verify: %v", err)
	}
	// wrong secret → mismatch
	if err := g.VerifyWebhook(h, body, "wrong"); err == nil {
		t.Error("a wrong secret must fail verification")
	}
	// missing header → error
	if err := g.VerifyWebhook(http.Header{}, body, secret); err == nil {
		t.Error("a missing signature header must fail")
	}
	// tampered body → mismatch
	if err := g.VerifyWebhook(h, []byte(`{"repository":{"html_url":"https://github.com/evil/x"}}`), secret); err == nil {
		t.Error("a tampered body must fail verification")
	}
}

func TestGitLab_VerifyWebhook(t *testing.T) {
	gl := NewGitLab("a", "b")
	h := http.Header{}
	h.Set("X-Gitlab-Token", "shh")
	if err := gl.VerifyWebhook(h, nil, "shh"); err != nil {
		t.Fatalf("a matching token should verify: %v", err)
	}
	if err := gl.VerifyWebhook(h, nil, "wrong"); err == nil {
		t.Error("a wrong token must fail")
	}
	if err := gl.VerifyWebhook(http.Header{}, nil, "shh"); err == nil {
		t.Error("a missing token header must fail")
	}
}

// Both connectors satisfy the WebhookVerifier capability.
func TestWebhookVerifier_Implemented(t *testing.T) {
	var _ WebhookVerifier = NewGitHub("a", "b")
	var _ WebhookVerifier = NewGitLab("a", "b")
}

func TestGitHub_RegisterWebhook(t *testing.T) {
	var gotPath, gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"id":1}`))
	}))
	defer srv.Close()
	g := NewGitHub("a", "b")
	g.APIBase = srv.URL
	g.HTTP = srv.Client()
	if err := g.RegisterWebhook(context.Background(), "tok", "acme/web", "https://app/v1/webhooks/github", "shh"); err != nil {
		t.Fatal(err)
	}
	if gotPath != "/repos/acme/web/hooks" {
		t.Errorf("wrong hook path: %s", gotPath)
	}
	for _, want := range []string{`"push"`, `"https://app/v1/webhooks/github"`, `"shh"`, `"content_type":"json"`} {
		if !strings.Contains(gotBody, want) {
			t.Errorf("hook body missing %q: %s", want, gotBody)
		}
	}
}

func TestGitHub_RegisterWebhook_Idempotent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		_, _ = w.Write([]byte(`{"message":"Validation Failed","errors":[{"message":"Hook already exists on this repository"}]}`))
	}))
	defer srv.Close()
	g := NewGitHub("a", "b")
	g.APIBase = srv.URL
	g.HTTP = srv.Client()
	if err := g.RegisterWebhook(context.Background(), "tok", "acme/web", "https://app/cb", "shh"); err != nil {
		t.Errorf("an already-existing hook should be a no-op success, got %v", err)
	}
}
