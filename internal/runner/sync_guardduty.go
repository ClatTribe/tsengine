package runner

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/ClatTribe/tsengine/internal/connector/awsfetch"
	"github.com/ClatTribe/tsengine/internal/l15"
	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// GuardDutyResult is what one GuardDuty read did.
type GuardDutyResult struct {
	Connections []string          `json:"connections"`           // read
	NotEnabled  []string          `json:"not_enabled,omitempty"` // connection ids whose region has no GuardDuty detector
	Failed      map[string]string `json:"failed,omitempty"`
	Findings    []types.Finding   `json:"findings"`
	Truncated   []string          `json:"truncated,omitempty"`
}

// SyncGuardDuty reads the findings AWS GuardDuty raised in each connected AWS account and stores them.
//
// GuardDuty is AWS's own threat detector; its findings are carried as GuardDuty's, with GuardDuty's
// severity, never re-judged here. What this adds is that they reach the product at all: a customer who
// turned GuardDuty on had its alerts in the AWS console and nowhere else, so an instance mining crypto or
// a credential used from outside AWS was invisible to the incident queue, the escalation matrix and the
// AI engineer.
//
// Grounded (§10): a region with GuardDuty switched off is NOT a clean account — nothing is watching — so
// it is reported in NotEnabled and never counted as read. A failed read is named and does not advance the
// cursor. Findings are events (detect.IsEventProducer): a person closes them, not a later quiet read.
func (s *Service) SyncGuardDuty(ctx context.Context, tenantID string) (GuardDutyResult, bool) {
	defer lockEvents(tenantID)()
	res := GuardDutyResult{Findings: []types.Finding{}, Failed: map[string]string{}}
	if s.Store == nil || s.GuardDutyReader == nil {
		return res, false
	}
	t, err := s.Store.GetTenant(ctx, tenantID)
	if err != nil {
		return res, false
	}
	conns, err := s.Store.ListConnections(ctx, tenantID)
	if err != nil {
		return res, false
	}
	now := s.now()
	latest := map[string]time.Time{}
	var found []types.Finding
	for _, c := range conns {
		if c.Kind != platform.ConnAWS || c.Status != platform.ConnActive {
			continue
		}
		reader := s.GuardDutyReader(c)
		if reader == nil {
			res.Failed[c.ID] = "no GuardDuty reader for this connection"
			continue
		}
		since := now.Add(-CloudEventWindow)
		if cur := t.GuardDutyCursors[c.ID]; !cur.IsZero() && cur.Add(-CloudEventOverlap).After(since) {
			since = cur.Add(-CloudEventOverlap)
		}
		page, ferr := reader.FindingsSince(ctx, since)
		if page.NotEnabled || errors.Is(ferr, awsfetch.ErrGuardDutyNotEnabled) {
			res.NotEnabled = append(res.NotEnabled, c.ID)
			continue
		}
		if ferr != nil {
			res.Failed[c.ID] = ferr.Error()
			slog.Warn("[scan] guardduty not read", "tenant", tenantID, "connection", c.ID, "err", ferr.Error())
			continue
		}
		res.Connections = append(res.Connections, c.ID)
		if page.Truncated {
			res.Truncated = append(res.Truncated, c.ID)
		}
		if !page.Latest.IsZero() {
			latest[c.ID] = page.Latest
		}
		found = append(found, guardDutyFindings(page.Findings)...)
	}
	if len(res.Connections) == 0 {
		return res, false
	}
	found = l15.Enrich(found)
	for i := range found {
		found[i].ID = eventFindingID("gd", found[i])
		if err := s.Store.PutFinding(ctx, tenantID, found[i]); err != nil {
			slog.Warn("[scan] guardduty finding could not be stored", "tenant", tenantID, "rule", found[i].RuleID, "err", err.Error())
			continue
		}
		res.Findings = append(res.Findings, found[i])
	}
	s.foldPosture(ctx, tenantID, res.Findings)
	if t.GuardDutyCursors == nil {
		t.GuardDutyCursors = map[string]time.Time{}
	}
	for k, v := range latest {
		if v.After(t.GuardDutyCursors[k]) {
			t.GuardDutyCursors[k] = v
		}
	}
	if t.PostureAssessed == nil {
		t.PostureAssessed = map[string]time.Time{}
	}
	t.PostureAssessed["guardduty"] = now
	if err := s.Store.PutTenant(ctx, t); err != nil {
		slog.Warn("[scan] guardduty cursor not saved", "tenant", tenantID, "err", err.Error())
	}
	return res, true
}

// guardDutySeverity is GuardDuty's own banding of its 1.0–10.0 score.
func guardDutySeverity(score float64) types.Severity {
	switch {
	case score >= 9:
		return types.SeverityCritical
	case score >= 7:
		return types.SeverityHigh
	case score >= 4:
		return types.SeverityMedium
	case score > 0:
		return types.SeverityLow
	}
	return types.SeverityInfo
}

func guardDutyFindings(in []awsfetch.GuardDutyFinding) []types.Finding {
	out := make([]types.Finding, 0, len(in))
	for _, g := range in {
		if strings.TrimSpace(g.Type) == "" {
			continue
		}
		f := types.Finding{
			RuleID: "guardduty::" + g.Type, Tool: "guardduty", Severity: guardDutySeverity(g.Severity),
			Endpoint: "cloud:" + firstNonEmpty(g.Resource, g.Type), Title: firstNonEmpty(g.Title, g.Type),
			Description: fmt.Sprintf("Reported by AWS GuardDuty (severity %.1f%s). %s", g.Severity, regionSuffix(g.Region), g.Description),
			ToolArgs:    map[string]string{"event_id": g.ID, "guardduty_type": g.Type},
		}
		out = append(out, f)
	}
	return out
}

func firstNonEmpty(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return a
	}
	return b
}

func regionSuffix(r string) string {
	if r == "" {
		return ""
	}
	return ", " + r
}
