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

// Discord posts a heads-up to a Discord Incoming Webhook when continuous monitoring opens a
// new incident — the Discord analogue of the Slack/Teams heads-up, for the many SMB/startup
// teams whose ops channel lives in Discord. Implements the alerter shape (IncidentOpened) so
// it composes into MultiAlerter alongside Slack/Teams/PagerDuty. Nil/empty WebhookURL is a no-op.
//
// Unlike the generic Webhook notifier (a raw signed JSON event for machines), this renders a
// human-readable, colour-coded Discord embed. Severity-gated to high/critical by default so a
// channel isn't buried in low-priority noise.
type Discord struct {
	WebhookURL  string       // Discord Incoming Webhook URL
	MinSeverity string       // gate: "" or "high" → only high/critical; "all" → everything
	HTTP        *http.Client // overridable for tests
}

// NewDiscord builds the alerter with a sensible default (high/critical only).
func NewDiscord(webhookURL string) *Discord {
	return &Discord{WebhookURL: webhookURL, HTTP: &http.Client{Timeout: 10 * time.Second}}
}

func (d *Discord) client() *http.Client {
	if d.HTTP != nil {
		return d.HTTP
	}
	return http.DefaultClient
}

// IncidentOpened posts the incident embed. Best-effort: returns the HTTP error so MultiAlerter
// can record it, but callers treat alerting as non-fatal.
func (d *Discord) IncidentOpened(ctx context.Context, inc platform.Incident) error {
	if d == nil || d.WebhookURL == "" {
		return nil
	}
	if d.MinSeverity != "all" && !pagesSeverity(inc.Severity) {
		return nil // high/critical only by default — quieter issues stay on the dashboard
	}

	title := fmt.Sprintf("🛡️ TensorShield — new %s issue", inc.Severity)
	if inc.Attacked {
		title = fmt.Sprintf("🚨 TensorShield — %s issue UNDER ACTIVE ATTACK", inc.Severity)
	}
	payload := map[string]any{
		"embeds": []map[string]any{{
			"title":       title,
			"description": inc.Title,
			"color":       discordColor(inc.Severity),
			"fields": []map[string]any{
				{"name": "Severity", "value": nz(inc.Severity, "—"), "inline": true},
				{"name": "Rule", "value": nz(inc.RuleID, "—"), "inline": true},
				{"name": "Finding", "value": nz(inc.FindingID, "—"), "inline": true},
			},
		}},
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.WebhookURL, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := d.client().Do(req)
	if err != nil {
		return fmt.Errorf("discord notify: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 { // Discord returns 204 No Content on success
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
		return fmt.Errorf("discord notify: http %d: %s", resp.StatusCode, b)
	}
	return nil
}

// discordColor maps severity to an embed accent colour (decimal RGB, the format Discord wants).
func discordColor(sev string) int {
	switch sev {
	case "critical":
		return 0xB00020
	case "high":
		return 0xD93F0B
	case "medium":
		return 0xD9A406
	default:
		return 0x2563EB
	}
}
