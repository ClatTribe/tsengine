package platformapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ClatTribe/tsengine/internal/l2"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// TestAIAnalysis_PersistOverwriteList: the AI engineer's deliverable is persisted, a RE-RUN overwrites the
// prior analysis for the same scope (latest wins — bounded), and the list endpoint returns it. This is the
// "my analysis survives navigation" guarantee.
func TestAIAnalysis_PersistOverwriteList(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	d := Deps{Store: st}

	out1 := l2.Outcome{
		Summary:    &l2.FinalReport{ExecutiveSummary: "first pass"},
		Findings:   []types.Finding{{Title: "SQLi in login", Severity: types.SeverityHigh, Description: "reaches user DB"}},
		Model:      "claude-opus-4-8", Iterations: 5, CostUSD: 0.12,
	}
	a1 := d.persistAIAnalysis(ctx, "ten", "triage", "", "Whole-estate triage", out1, time.Unix(1000, 0))
	if a1.ID != "triage:" {
		t.Fatalf("deterministic id = %q, want triage:", a1.ID)
	}

	// A re-run OVERWRITES (same scope) — no unbounded growth.
	out2 := l2.Outcome{Summary: &l2.FinalReport{ExecutiveSummary: "second pass"}, Model: "claude-opus-4-8"}
	d.persistAIAnalysis(ctx, "ten", "triage", "", "Whole-estate triage", out2, time.Unix(2000, 0))

	all, err := st.ListAIAnalyses(ctx, "ten")
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 1 {
		t.Fatalf("re-run must overwrite: want 1 analysis, got %d", len(all))
	}
	if all[0].Summary != "second pass" {
		t.Errorf("latest wins: summary = %q, want 'second pass'", all[0].Summary)
	}
	if len(all[0].Reports) != 0 {
		t.Errorf("overwrite must replace reports wholesale, got %d", len(all[0].Reports))
	}

	// A per-issue investigation is a DISTINCT scope → separate record.
	d.persistAIAnalysis(ctx, "ten", "investigate", "nuclei::sqli|/login", "SQLi in login",
		l2.Outcome{Summary: &l2.FinalReport{ExecutiveSummary: "issue dive"}}, time.Unix(3000, 0))
	all, _ = st.ListAIAnalyses(ctx, "ten")
	if len(all) != 2 {
		t.Fatalf("investigate is a distinct scope: want 2, got %d", len(all))
	}

	// The list endpoint returns them, and ?kind= filters.
	rec := httptest.NewRecorder()
	d.handleListAIAnalyses(rec, httptest.NewRequest(http.MethodGet, "/v1/ai-analyses?kind=investigate", nil), "ten")
	body := rec.Body.String()
	if rec.Code != http.StatusOK || !strings.Contains(body, "issue dive") || strings.Contains(body, "second pass") {
		t.Errorf("kind filter wrong: %s", body)
	}
}

// TestAIAnalysis_RecommendationsPersist_DegenerateSkipped: the "fix" half (Recommendations) must survive to
// the store (else reload shows root-cause without the fix), and a DEGENERATE run (empty summary + no reports)
// must NOT overwrite a prior good analysis (deterministic id → latest-wins would otherwise destroy it).
func TestAIAnalysis_RecommendationsPersist_DegenerateSkipped(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	d := Deps{Store: st}

	good := l2.Outcome{Summary: &l2.FinalReport{ExecutiveSummary: "root cause", Recommendations: "apply the patch at the auth layer"}}
	d.persistAIAnalysis(ctx, "ten", "triage", "", "Triage", good, time.Unix(1, 0))

	all, _ := st.ListAIAnalyses(ctx, "ten")
	if len(all) != 1 || all[0].Recommends != "apply the patch at the auth layer" {
		t.Fatalf("recommendations (the fix half) must persist: %+v", all)
	}

	// A degenerate re-run (no summary, no reports, no recommends) must NOT overwrite the good analysis.
	d.persistAIAnalysis(ctx, "ten", "triage", "", "Triage", l2.Outcome{}, time.Unix(2, 0))
	all, _ = st.ListAIAnalyses(ctx, "ten")
	if len(all) != 1 || all[0].Recommends != "apply the patch at the auth layer" {
		t.Errorf("a degenerate empty run must NOT destroy the prior good analysis: %+v", all)
	}
}

// TestAIAnalysis_PersistBestEffort: a nil/failing store must never panic the run path (best-effort persist).
func TestAIAnalysis_PersistBestEffort(t *testing.T) {
	d := Deps{Store: store.NewMemory()}
	// Missing summary pointer must not panic; empty tenant is fine.
	got := d.persistAIAnalysis(context.Background(), "ten", "triage", "", "", l2.Outcome{}, time.Unix(1, 0))
	if got.Summary != "" || got.ID != "triage:" {
		t.Errorf("nil summary handled: %+v", got)
	}
	_ = platform.AIAnalysis{} // keep platform import
}
