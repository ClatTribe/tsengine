package connector

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
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
