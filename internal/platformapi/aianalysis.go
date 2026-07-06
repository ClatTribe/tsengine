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
	a := platform.AIAnalysis{
		ID:         platform.AIAnalysisID(kind, scope),
		TenantID:   tenantID,
		Kind:       kind,
		Scope:      scope,
		Title:      title,
		Reports:    reportsFromFindings(out.Findings),
		Model:      out.Model,
		Iterations: out.Iterations,
		CostUSD:    out.CostUSD,
		CreatedAt:  now,
	}
	if out.Summary != nil {
		a.Summary = out.Summary.ExecutiveSummary
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
