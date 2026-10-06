package platformapi

import (
	"context"
	"net/http"
	"time"

	"github.com/ClatTribe/tsengine/internal/l2"
	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// aianalysis.go persists + serves the AI Security Engineer's deliverables (Triage / Investigate / Cloud), so
// an SMB user's analysis SURVIVES navigation instead of vanishing with the HTTP response. The store holds the
// LATEST analysis per scope (deterministic id = kind:scope → a re-run overwrites), so it never grows unbounded
// and "show my last analysis" is a single lookup. Persistence is BEST-EFFORT: a store failure is logged and
// swallowed — it must never turn a successful, already-charged LLM run into an error for the user.

// persistAIAnalysis records an L2 Outcome as the tenant's latest analysis for (kind, scope). now is passed in
// so the caller controls the timestamp (testable). Returns the stored record (for the caller to echo).
func (d Deps) persistAIAnalysis(ctx context.Context, tenantID, kind, scope, title string, out l2.Outcome, now time.Time) platform.AIAnalysis {
	// Spend first, and unconditionally: a run that produced nothing worth persisting was still paid for.
	surface := "estate"
	if kind == "investigate" {
		surface = "issue"
	}
	d.recordAISpend(ctx, tenantID, kind, surface, out.CostUSD, out.CostUSD > 0 || out.Tokens > 0, out.Model, countVerified(out.Findings))
	a := platform.AIAnalysis{
		ID:         platform.AIAnalysisID(kind, scope),
		TenantID:   tenantID,
		Kind:       kind,
		Scope:      scope,
		Title:      title,
		Reports:    reportsFromFindings(out.Findings),
		Model:      out.Model,
		Iterations: out.Iterations,
		CostUSD:    analysisCost(d, ctx, tenantID, out),
		CreatedAt:  now,
	}
	if out.Summary != nil {
		a.Summary = out.Summary.ExecutiveSummary
		a.Recommends = out.Summary.Recommendations // the "fix" half — must persist so reload isn't degraded
		a.Methodology = out.Summary.Methodology
	}
	// Don't OVERWRITE a prior good analysis with a degenerate empty one: because the id is deterministic
	// (latest-wins), a hiccup run (LLM returned no summary + no reports — e.g. budget exhausted) would
	// otherwise destroy the tenant's last useful brief. A run with no content is not worth persisting.
	if a.Summary == "" && a.Recommends == "" && len(a.Reports) == 0 {
		return a
	}
	if err := d.Store.PutAIAnalysis(ctx, a); err != nil && d.Recorder != nil {
		d.Recorder.Record("ai analysis persist failed", "platform",
			map[string]any{"tenant_id": tenantID, "kind": kind, "error": err.Error()}, "best-effort, run still returned")
	}
	return a
}

// reportsFromFindings maps the agent's per-issue findings into the persisted report shape.
func reportsFromFindings(fs []types.Finding) []platform.AIReport {
	out := make([]platform.AIReport, 0, len(fs))
	for _, f := range fs {
		out = append(out, platform.AIReport{
			Title:    firstNonEmpty(f.Title, f.RuleID),
			Severity: string(f.Severity),
			Body:     f.Description,
		})
	}
	return out
}

// handleListAIAnalyses returns the tenant's persisted AI analyses (latest per scope). Optional ?kind= filter.
func (d Deps) handleListAIAnalyses(w http.ResponseWriter, r *http.Request, tenantID string) {
	all, err := d.Store.ListAIAnalyses(r.Context(), tenantID)
	if err != nil {
		respond(w, nil, err)
		return
	}
	kind := r.URL.Query().Get("kind")
	out := make([]platform.AIAnalysis, 0, len(all))
	for _, a := range all {
		if kind == "" || a.Kind == kind {
			out = append(out, a)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"analyses": out})
}

// analysisCost is the cost shown on a persisted analysis. A self-hosted run is $0 here too: the monthly
// budget still reads AIAnalysis.CostUSD for the month the spend record shipped (max of the two), so a
// priced self-hosted run left here would keep charging the budget through the back door.
func analysisCost(d Deps, ctx context.Context, tenantID string, out l2.Outcome) float64 {
	if d.selfHostedModel(ctx, tenantID, out.Model) {
		return 0
	}
	return out.CostUSD
}
