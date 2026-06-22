package notify

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/ClatTribe/tsengine/pkg/platform"
)

// Webhook posts a generic, signed JSON event to a tenant-configured URL when continuous
// monitoring opens a new incident. Unlike the Slack/Teams notifiers (which speak a specific
// chat-card format), this is the UNIVERSAL integration primitive an SMB asks for: one webhook
// wires TensorShield into anything — Zapier, Make, n8n, a Discord/Mattermost webhook, a SIEM, a
// custom dashboard — without us building a bespoke connector per destination. Implements the
// alerter shape (IncidentOpened) so it composes into MultiAlerter alongside Slack/Teams/PagerDuty.
// Nil/empty URL is a no-op.
//
// Every request carries an HMAC-SHA256 signature over the raw body in the X-TensorShield-Signature
// header ("sha256=<hex>"), keyed by Secret, so the receiver can verify the event is authentic and
// untampered — the same scheme as the platform's INBOUND webhook verification, mirrored outbound.
type Webhook struct {
	URL    string
	Secret string // HMAC-SHA256 signing key; empty → the signature header is omitted (unsigned)
	// MinSeverity gates delivery: "all" (default) sends every incident — a webhook is
	// machine-consumed, so the receiver filters; "high" → only high/critical.
	MinSeverity string
	HTTP        *http.Client // overridable for tests
}

// NewWebhook builds the notifier. A generic webhook is machine-consumed, so it defaults to sending
// EVERY incident (the receiver decides what to do) rather than the human-channel high/critical gate.
func NewWebhook(url, secret string) *Webhook {
	return &Webhook{URL: url, Secret: secret, MinSeverity: "all", HTTP: &http.Client{Timeout: 10 * time.Second}}
}

func (wh *Webhook) client() *http.Client {
	if wh.HTTP != nil {
		return wh.HTTP
	}
	return http.DefaultClient
}

// WebhookEvent is the stable, machine-readable payload. Versioned so receivers can evolve safely.
type WebhookEvent struct {
	Version    string `json:"version"`
	Type       string `json:"type"` // "incident.opened"
	Tenant     string `json:"tenant"`
	IncidentID string `json:"incident_id"`
	Key        string `json:"key"`
	RuleID     string `json:"rule_id"`
	Title      string `json:"title"`
	Severity   string `json:"severity"`
	FindingID  string `json:"finding_id,omitempty"`
	Attacked   bool   `json:"attacked,omitempty"`
	OpenedAt   string `json:"opened_at"`
}

// IncidentOpened delivers the signed event. Best-effort: returns the error so MultiAlerter can
// record it, but callers treat alerting as non-fatal.
func (wh *Webhook) IncidentOpened(ctx context.Context, inc platform.Incident) error {
	if wh == nil || wh.URL == "" {
		return nil
	}
	if wh.MinSeverity == "high" && !pagesSeverity(inc.Severity) {
		return nil
	}
	ev := WebhookEvent{
		Version: "1", Type: "incident.opened", Tenant: inc.TenantID,
		IncidentID: inc.ID, Key: inc.Key, RuleID: inc.RuleID, Title: inc.Title,
		Severity: inc.Severity, FindingID: inc.FindingID, Attacked: inc.Attacked,
		OpenedAt: inc.OpenedAt.UTC().Format(time.RFC3339),
	}
	raw, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, wh.URL, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "TensorShield-Webhook/1.0")
	req.Header.Set("X-TensorShield-Event", ev.Type)
	if wh.Secret != "" {
		req.Header.Set("X-TensorShield-Signature", "sha256="+Sign(wh.Secret, raw))
	}
	resp, err := wh.client().Do(req)
	if err != nil {
		return fmt.Errorf("webhook notify: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
		return fmt.Errorf("webhook notify: http %d: %s", resp.StatusCode, b)
	}
	return nil
}

// Sign returns the lowercase-hex HMAC-SHA256 of body keyed by secret — the value (after the
// "sha256=" prefix) a receiver recomputes over the raw request body to verify authenticity.
func Sign(secret string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}
