// Package notify pushes platform events to where the human desk lives — Slack for the
// MVP (docs/autonomous-team.md §3.4). Its one job today: when a tier-gated remediation
// queues for approval, post it to the Kanpur analyst's channel with Approve/Reject
// buttons that POST back to the platform's Slack interactive endpoint.
package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/ClatTribe/tsengine/pkg/platform"
)

// Notifier delivers an approval request somewhere a human will see it. Nil-safe: a nil
// Notifier is a no-op so the desk can call it unconditionally.
type Notifier interface {
	ApprovalNeeded(ctx context.Context, a platform.Action) error
}

// Slack posts approval requests to a Slack Incoming Webhook (or a Block Kit-capable
// endpoint). WebhookURL is the destination; HTTP is overridable for tests.
type Slack struct {
	WebhookURL string
	HTTP       *http.Client
}

// NewSlack builds a Slack notifier.
func NewSlack(webhookURL string) *Slack {
	return &Slack{WebhookURL: webhookURL, HTTP: &http.Client{Timeout: 10 * time.Second}}
}

func (s *Slack) client() *http.Client {
	if s.HTTP != nil {
		return s.HTTP
	}
	return http.DefaultClient
}

// ApprovalNeeded posts a Block Kit message with Approve/Reject buttons whose value is
// the action id, so the interactive callback can resolve + decide it.
func (s *Slack) ApprovalNeeded(ctx context.Context, a platform.Action) error {
	if s == nil || s.WebhookURL == "" {
		return nil
	}
	msg := slackMessage(a)
	body, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.WebhookURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.client().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("notify: slack returned %d", resp.StatusCode)
	}
	return nil
}

// slackMessage renders the Block Kit payload. The button action_ids (approve/reject)
// and value (the action id, scoped with the tenant) drive the interactive callback.
func slackMessage(a platform.Action) map[string]any {
	value := a.TenantID + ":" + a.ID
	text := fmt.Sprintf("*Approval needed* — `%s` (tier %d)\n%s\nfinding `%s`", a.Kind, a.Tier, nz(a.Title, a.ID), a.FindingID)
	return map[string]any{
		"text": "Approval needed: " + a.ID,
		"blocks": []any{
			map[string]any{
				"type": "section",
				"text": map[string]any{"type": "mrkdwn", "text": text},
			},
			map[string]any{
				"type": "actions",
				"elements": []any{
					map[string]any{
						"type":      "button",
						"action_id": "approve",
						"style":     "primary",
						"text":      map[string]any{"type": "plain_text", "text": "Approve"},
						"value":     value,
					},
					map[string]any{
						"type":      "button",
						"action_id": "reject",
						"style":     "danger",
						"text":      map[string]any{"type": "plain_text", "text": "Reject"},
						"value":     value,
					},
				},
			},
		},
	}
}

func nz(s, def string) string {
	if s == "" {
		return def
	}
	return s
}
