package platformapi

import (
	"context"
	"net/http"
	"time"

	"github.com/ClatTribe/tsengine/internal/aibudget"
	"github.com/ClatTribe/tsengine/internal/crossdetect"
	"github.com/ClatTribe/tsengine/internal/store"
)

// aibudget.go: GET /v1/ai-budget — the capital-allocation PLAN (where the next AI tokens should go).
//
// The twin of ai-value: that view says what each surface's tokens BOUGHT; this one recommends where
// the next tokens should GO. It reads the same AISpend rows (never writes them), the tenant's open
// issues, and its assets, and returns a ranked, costed per-surface plan. Grounded + LLM-free: the
// allocator spends no tokens of its own, and a surface with no open exposure gets nothing.
func (d Deps) handleAIBudget(w http.ResponseWriter, r *http.Request, tenantID string) {
	ctx := r.Context()

	open, err := d.openNonIgnoredIssues(ctx, tenantID)
	if err != nil {
		respond(w, nil, err)
		return
	}
	assets, err := d.Store.ListAssets(ctx, tenantID)
	if err != nil {
		respond(w, nil, err)
		return
	}
	spend, err := d.Store.ListAISpend(ctx, tenantID)
	if err != nil {
		respond(w, nil, err)
		return
	}
	// Window the spend to the same 30 days ai-value uses, so "measured yield" means recent behaviour,
	// not a run from months ago on a codebase that has since changed.
	since := time.Now().UTC().AddDate(0, 0, -30)
	recent := spend[:0:0]
	for _, s := range spend {
		if !s.At.Before(since) {
			recent = append(recent, s)
		}
	}

	var budget float64
	if t, err := d.Store.GetTenant(ctx, tenantID); err == nil {
		budget = t.MonthlyAIBudgetUSD
	}

	plan := aibudget.Build(aibudget.Inputs{
		Budget:          budget,
		ModelConfigured: d.resolveAgentLLM(ctx, tenantID) != nil,
		OpenIssues:      open,
		Assets:          assets,
		Spend:           recent,
	})
	respond(w, plan, nil)
}

// openNonIgnoredIssues is the active issue list the allocator ranks: findings unified into issues,
// with excluded noise dropped and still-suppressing ignore rules removed (a lapsed rule returns its
// issue to the list). It mirrors handleIssues' default (non-ignored) view so the allocator ranks the
// same issues the operator sees on /issues.
func (d Deps) openNonIgnoredIssues(ctx context.Context, tenantID string) ([]crossdetect.Issue, error) {
	findings, err := d.Store.ListFindings(ctx, tenantID, store.FindingFilter{})
	if err != nil {
		return nil, err
	}
	excl, err := d.Store.ListExclusionRules(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	rules, err := d.Store.ListIgnoreRules(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	suppressed := map[string]bool{}
	for _, ir := range rules {
		if ir.Suppresses(now) {
			suppressed[ir.IssueKey] = true
		}
	}
	findings = crossdetect.ApplyExclusions(findings, excl)
	out := []crossdetect.Issue{}
	for _, i := range crossdetect.UnifiedIssues(findings) {
		if !suppressed[i.Key] {
			out = append(out, i)
		}
	}
	return out, nil
}
