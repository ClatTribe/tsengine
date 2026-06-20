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

// Teams posts a heads-up to a Microsoft Teams Incoming Webhook when continuous
// monitoring opens a new incident — the Teams analogue of the Slack heads-up, for
// the many SMBs on Microsoft 365 rather than Slack. Implements the alerter shape
// (IncidentOpened) structurally, so it composes into MultiAlerter alongside Slack
// + PagerDuty. Nil/empty WebhookURL is a no-op.
//
// Uses the legacy MessageCard payload (the format Teams Incoming Webhooks accept
// without an app manifest) — a colour-coded card with the incident's severity,
// title, rule, and tenant. Severity-gated to high/critical by default so a Teams
// channel isn't buried in low-priority noise.
type Teams struct {
	WebhookURL  string       // Teams Incoming Webhook URL
	MinSeverity string       // gate: "" or "high" → only high/critical; "all" → everything
	HTTP        *http.Client // overridable for tests
}

// NewTeams builds the alerter with a sensible default (high/critical only).
func NewTeams(webhookURL string) *Teams {
	return &Teams{WebhookURL: webhookURL, HTTP: &http.Client{Timeout: 10 * time.Second}}
}

func (t *Teams) client() *http.Client {
	if t.HTTP != nil {
		return t.HTTP
	}
	return http.DefaultClient
}

// IncidentOpened posts the incident card. Best-effort: returns the HTTP error so
// MultiAlerter can record it, but callers treat alerting as non-fatal.
func (t *Teams) IncidentOpened(ctx context.Context, inc platform.Incident) error {
	if t == nil || t.WebhookURL == "" {
		return nil
	}
	if t.MinSeverity != "all" && !pagesSeverity(inc.Severity) {
		return nil // high/critical only by default — quieter issues stay on the dashboard
	}

	card := map[string]any{
		"@type":      "MessageCard",
		"@context":   "https://schema.org/extensions",
		"summary":    fmt.Sprintf("New %s issue: %s", inc.Severity, inc.Title),
		"themeColor": teamsColor(inc.Severity),
		"title":      fmt.Sprintf("🛡️ TensorShield — new %s issue", inc.Severity),
		"sections": []map[string]any{{
			"activityTitle": inc.Title,
			"facts": []map[string]string{
				{"name": "Severity", "value": inc.Severity},
				{"name": "Rule", "value": inc.RuleID},
				{"name": "Finding", "value": inc.FindingID},
				{"name": "Tenant", "value": inc.TenantID},
			},
			"markdown": true,
		}},
	}
	raw, err := json.Marshal(card)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.WebhookURL, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := t.client().Do(req)
	if err != nil {
		return fmt.Errorf("teams notify: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
		return fmt.Errorf("teams notify: http %d: %s", resp.StatusCode, b)
	}
	return nil
}

// teamsColor maps severity to a card accent colour (hex, no #).
func teamsColor(sev string) string {
	switch sev {
	case "critical":
		return "B00020"
	case "high":
		return "D93F0B"
	case "medium":
		return "D9A406"
	default:
		return "2563EB"
	}
}
