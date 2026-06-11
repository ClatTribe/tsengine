package connector

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"
)

// VerifyWebhook authenticates a GitHub webhook: HMAC-SHA256 of the raw body keyed by the
// shared secret must match the X-Hub-Signature-256 header (constant-time). This is what
// stops a spoofed push payload from forcing re-scans.
func (g *GitHub) VerifyWebhook(h http.Header, body []byte, secret string) error {
	got := h.Get("X-Hub-Signature-256")
	if got == "" {
		return errors.New("github: missing X-Hub-Signature-256")
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	want := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	if subtle.ConstantTimeCompare([]byte(got), []byte(want)) != 1 {
		return errors.New("github: webhook signature mismatch")
	}
	return nil
}

// VerifyWebhook authenticates a GitLab webhook: the X-Gitlab-Token header must equal the
// shared secret (GitLab uses a plain shared token, not an HMAC), compared constant-time.
func (g *GitLab) VerifyWebhook(h http.Header, _ []byte, secret string) error {
	got := strings.TrimSpace(h.Get("X-Gitlab-Token"))
	if got == "" {
		return errors.New("gitlab: missing X-Gitlab-Token")
	}
	if subtle.ConstantTimeCompare([]byte(got), []byte(secret)) != 1 {
		return errors.New("gitlab: webhook token mismatch")
	}
	return nil
}
