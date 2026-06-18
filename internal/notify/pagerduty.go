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

// PagerDuty triggers a PagerDuty Events API v2 incident when continuous monitoring opens a
// new high/critical issue — the on-call PAGE (a human gets woken), as opposed to Slack's
// passive heads-up. Implements detect.Alerter (IncidentOpened) structurally. Severity-gated:
// only high/critical page by default — info/medium would just be pager noise.
type PagerDuty struct {
	RoutingKey string       // PagerDuty Events API v2 integration (routing) key
	EventsURL  string       // override for tests; default = pagerDutyEventsURL
	HTTP       *http.Client // overridable for tests
}

const pagerDutyEventsURL = "https://events.pagerduty.com/v2/enqueue"

// NewPagerDuty builds the alerter.
func NewPagerDuty(routingKey string) *PagerDuty {
	return &PagerDuty{RoutingKey: routingKey, EventsURL: pagerDutyEventsURL, HTTP: &http.Client{Timeout: 10 * time.Second}}
}

func (p *PagerDuty) client() *http.Client {
	if p.HTTP != nil {
		return p.HTTP
	}
	return http.DefaultClient
}

func (p *PagerDuty) url() string {
	if p.EventsURL != "" {
		return p.EventsURL
	}
	return pagerDutyEventsURL
}

// IncidentOpened triggers a PagerDuty event for a new high/critical incident. dedup_key =
// the incident id, so a re-open of the same issue coalesces rather than re-paging.
func (p *PagerDuty) IncidentOpened(ctx context.Context, inc platform.Incident) error {
	if p == nil || p.RoutingKey == "" {
		return nil
	}
	if !pagesSeverity(inc.Severity) {
		return nil // only high/critical page; quieter issues stay on the dashboard
	}
	body := map[string]any{
		"routing_key":  p.RoutingKey,
		"event_action": "trigger",
		"dedup_key":    inc.ID,
		"payload": map[string]any{
			"summary":   fmt.Sprintf("[tsengine] %s: %s", inc.Severity, inc.Title),
			"severity":  pdSeverity(inc.Severity),
			"source":    "tsengine",
			"component": inc.RuleID,
			"custom_details": map[string]any{
				"rule_id": inc.RuleID, "finding_id": inc.FindingID, "tenant_id": inc.TenantID,
			},
		},
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.url(), bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := p.client().Do(req)
	if err != nil {
		return fmt.Errorf("pagerduty trigger: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
		return fmt.Errorf("pagerduty trigger: http %d: %s", resp.StatusCode, b)
	}
	return nil
}

// pagesSeverity reports whether an incident severity is worth a page (vs dashboard-only).
func pagesSeverity(sev string) bool { return sev == "high" || sev == "critical" }

// pdSeverity maps our severity to PagerDuty's enum (critical|error|warning|info).
func pdSeverity(sev string) string {
	switch sev {
	case "critical":
		return "critical"
	case "high":
		return "error"
	case "medium":
		return "warning"
	default:
		return "info"
	}
}

// alerter is the structural shape of a detect.Alerter (kept local so notify needn't import
// detect — avoids a cycle).
type alerter interface {
	IncidentOpened(context.Context, platform.Incident) error
}

// MultiAlerter fans a new-incident alert out to several alerters, best-effort: one failing
// never blocks the others (so Slack + PagerDuty both fire). Nil/empty is a no-op.
type MultiAlerter []alerter

// IncidentOpened delivers to every child; returns the first error (callers treat alerting
// as best-effort, so this never fails the monitoring pass).
func (m MultiAlerter) IncidentOpened(ctx context.Context, inc platform.Incident) error {
	var firstErr error
	for _, a := range m {
		if a == nil {
			continue
		}
		if err := a.IncidentOpened(ctx, inc); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}
