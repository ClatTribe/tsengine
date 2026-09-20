package runner

import (
	"context"
	"log/slog"

	"github.com/ClatTribe/tsengine/internal/l15"
	"github.com/ClatTribe/tsengine/internal/sspm"
	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// syncOktaPosture reads the org's CONFIGURATION posture (sign-on rules, password and MFA-enrollment
// policies, API tokens, ThreatInsight) through the onboarded Okta token every monitoring pass — the
// same fetch as POST /v1/saas/okta/sync. Best-effort + grounded: no org URL, no active connection,
// no token, or a fetch that read nothing → the org was NOT observed and "sspm" is not covered by it.
func (s *Service) syncOktaPosture(ctx context.Context, tenantID string) ([]types.Finding, bool) {
	if s.Store == nil || s.Tokens == nil || s.NewID == nil || s.OktaOrgURL == "" {
		return nil, false
	}
	conns, err := s.Store.ListConnections(ctx, tenantID)
	if err != nil {
		return nil, false
	}
	var ok *platform.Connection
	for i := range conns {
		if conns[i].Kind == platform.ConnOkta && conns[i].Status == platform.ConnActive {
			ok = &conns[i]
			break
		}
	}
	if ok == nil {
		return nil, false
	}
	token, terr := s.Tokens.Resolve(ctx, *ok)
	if terr != nil || token == "" {
		return nil, false
	}
	org, ferr := sspm.FetchOktaPosture(ctx, s.OktaOrgURL, ok.Account, token, s.OktaHTTP)
	if ferr != nil {
		slog.Warn("[scan] okta posture not read", "tenant", tenantID, "err", ferr.Error())
		return nil, false
	}
	findings := l15.Enrich(sspm.AssessOkta(org, sspm.Options{}))
	saved := make([]types.Finding, 0, len(findings))
	for i := range findings {
		findings[i].ID = s.NewID()
		if err := s.Store.PutFinding(ctx, tenantID, findings[i]); err != nil {
			slog.Warn("[scan] okta posture finding could not be stored", "tenant", tenantID, "rule", findings[i].RuleID, "err", err.Error())
			continue
		}
		saved = append(saved, findings[i])
	}
	s.foldPosture(ctx, tenantID, saved)
	slog.Info("[scan] okta posture assessed", "tenant", tenantID, "org", org.Name, "findings", len(saved), "unread", len(org.Unread))
	return saved, true
}
