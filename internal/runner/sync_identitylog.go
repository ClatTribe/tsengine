package runner

import (
	"context"
	"log/slog"
	"time"

	"github.com/ClatTribe/tsengine/internal/identitylog"
	"github.com/ClatTribe/tsengine/internal/identitythreat"
	"github.com/ClatTribe/tsengine/internal/l15"
	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// IdentityLogResult is what one identity-threat sync did, for the manual door and the pass log.
type IdentityLogResult struct {
	Providers    []string          `json:"providers"`                // connection kinds actually read this pass
	Failed       map[string]string `json:"failed,omitempty"`         // kind → why the read failed
	Events       int               `json:"events"`                   // detector events after merge
	Findings     []types.Finding   `json:"findings"`                 // stored this pass
	Unmapped     map[string]int    `json:"unmapped,omitempty"`       // provider event types not translated
	ChecksNotRun map[string]string `json:"checks_not_run,omitempty"` // detector rules a provider cannot feed
}

// SyncIdentityLogs reads every connected identity provider's audit log since its cursor, runs the
// ITDR detector over the merged window, and stores the findings. This is what makes
// internal/identitythreat a LIVE capability: its nine rules existed with no source but a customer-
// built pusher, so they were execution-proven in tests and silent in production.
//
// Grounded (§10): no fetcher for a provider, no active connection, a token that cannot be resolved
// or a read that fails → that provider was NOT observed this pass (named in Failed), never an empty
// window that reads as "no attack". The cursor advances only past events actually read. `ran` is
// true only when at least one provider was read.
func (s *Service) SyncIdentityLogs(ctx context.Context, tenantID string) (IdentityLogResult, bool) {
	res := IdentityLogResult{Findings: []types.Finding{}, Failed: map[string]string{}, Unmapped: map[string]int{}, ChecksNotRun: map[string]string{}}
	if s.Store == nil || s.Tokens == nil || s.NewID == nil || len(s.IdentityLogFetchers) == 0 {
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
	var reports []identitylog.Report
	latest := map[string]time.Time{}
	for _, c := range conns {
		f := s.IdentityLogFetchers[c.Kind]
		if f == nil || c.Status != platform.ConnActive {
			continue
		}
		token, terr := s.Tokens.Resolve(ctx, c)
		if terr != nil || token == "" {
			res.Failed[c.Kind] = "credential could not be opened"
			slog.Warn("[scan] identity log not read — token unavailable", "tenant", tenantID, "provider", c.Kind)
			continue
		}
		since := identitylog.SinceFor(t.IdentityLogCursors[c.Kind], now)
		rep, ferr := f.Fetch(ctx, token, since)
		if ferr != nil {
			res.Failed[c.Kind] = ferr.Error()
			slog.Warn("[scan] identity log not read", "tenant", tenantID, "provider", c.Kind, "err", ferr.Error())
			continue
		}
		res.Providers = append(res.Providers, c.Kind)
		reports = append(reports, rep)
		for k, v := range rep.Unmapped {
			res.Unmapped[c.Kind+":"+k] += v
		}
		for k, v := range rep.ChecksNotRun {
			res.ChecksNotRun[c.Kind+":"+k] = v
		}
		if l := identitylog.Latest(rep); !l.IsZero() {
			latest[c.Kind] = l
		}
	}
	if len(reports) == 0 {
		return res, false
	}
	events := identitylog.Merge(reports...)
	res.Events = len(events)
	findings := identitythreat.Findings(identitythreat.Detect(events, identitythreat.Config{}))
	findings = l15.Enrich(findings) // §11 parity with POST /v1/identity/events
	for i := range findings {
		findings[i].ID = s.NewID()
		if err := s.Store.PutFinding(ctx, tenantID, findings[i]); err != nil {
			slog.Warn("[scan] identity-threat finding could not be stored", "tenant", tenantID, "rule", findings[i].RuleID, "err", err.Error())
			continue
		}
		res.Findings = append(res.Findings, findings[i])
	}
	s.foldPosture(ctx, tenantID, res.Findings)
	if t.IdentityLogCursors == nil {
		t.IdentityLogCursors = map[string]time.Time{}
	}
	for k, v := range latest {
		if v.After(t.IdentityLogCursors[k]) {
			t.IdentityLogCursors[k] = v
		}
	}
	if t.PostureAssessed == nil {
		t.PostureAssessed = map[string]time.Time{}
	}
	t.PostureAssessed["identitythreat"] = now
	if err := s.Store.PutTenant(ctx, t); err != nil {
		slog.Warn("[scan] identity-log cursor not saved", "tenant", tenantID, "err", err.Error())
	}
	slog.Info("[scan] identity audit logs assessed", "tenant", tenantID, "providers", res.Providers, "events", res.Events, "findings", len(res.Findings), "failed", len(res.Failed))
	return res, true
}
