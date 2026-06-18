package connector

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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

// RegisterWebhook creates a push webhook on a repo (target = "owner/repo") pointing at the
// platform's callback, secured by the shared secret. Idempotent: GitHub returns 422 when an
// identical hook already exists — treated as success.
func (g *GitHub) RegisterWebhook(ctx context.Context, token, target, callbackURL, secret string) error {
	body, _ := json.Marshal(map[string]any{
		"name": "web", "active": true, "events": []string{"push"},
		"config": map[string]string{"url": callbackURL, "content_type": "json", "secret": secret},
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		strings.TrimRight(g.APIBase, "/")+"/repos/"+target+"/hooks", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Content-Type", "application/json")
	resp, err := g.client().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		return nil
	case resp.StatusCode == http.StatusUnprocessableEntity && strings.Contains(string(rb), "already exists"):
		return nil // idempotent: the hook is already registered
	default:
		return fmt.Errorf("github: register webhook on %s: HTTP %d", target, resp.StatusCode)
	}
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
