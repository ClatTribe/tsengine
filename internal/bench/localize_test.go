package bench

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/internal/codelocalize"
)

// The substrate must actually localize: the LLM-free heuristic should put every planted sink in the
// top-3 across the built-in corpus. This is the measured-efficacy floor the user cares about.
func TestLocalizeScenarios_HeuristicRecall(t *testing.T) {
	scs := LocalizeScenarios()
	if len(scs) < 5 {
		t.Fatalf("need a multi-scenario corpus for a credible bench, got %d", len(scs))
	}
	scores, err := RunLocalize(context.Background(), codelocalize.HeuristicLocalizer{}, scs)
	if err != nil {
		t.Fatal(err)
	}
	agg := AggregateLocalize(scores)
	if agg.RecallAt3 < 1.0 {
		t.Fatalf("heuristic recall@3 should be perfect on planted sinks, got %.2f\n%s", agg.RecallAt3, RenderLocalize(scores))
	}
	if agg.RecallAt1 < 0.8 {
		t.Fatalf("heuristic recall@1 too low (%.2f) — the top rank should usually be the sink\n%s", agg.RecallAt1, RenderLocalize(scores))
	}
}

func TestScoreLocalize_Math(t *testing.T) {
	sc := LocalizeScenario{Name: "t", Truth: []string{"want.go"}}
	// truth at rank 4: recall@1=0, recall@3=0, recall@5=1, MRR=0.25.
	res := codelocalize.Result{Ranked: []codelocalize.Candidate{
		{Path: "a"}, {Path: "b"}, {Path: "c"}, {Path: "want.go"},
	}}
	s := ScoreLocalize(sc, res)
	if s.RecallAt1 != 0 || s.RecallAt3 != 0 || s.RecallAt5 != 1 {
		t.Fatalf("recall wrong: @1=%.2f @3=%.2f @5=%.2f", s.RecallAt1, s.RecallAt3, s.RecallAt5)
	}
	if s.MRR != 0.25 {
		t.Fatalf("MRR want 0.25 got %.2f", s.MRR)
	}
	if s.Found != 1 || s.Total != 1 {
		t.Fatalf("found/total wrong: %d/%d", s.Found, s.Total)
	}
}

func TestScoreLocalize_MissEntirely(t *testing.T) {
	sc := LocalizeScenario{Name: "t", Truth: []string{"missing.go"}}
	res := codelocalize.Result{Ranked: []codelocalize.Candidate{{Path: "a"}, {Path: "b"}}}
	s := ScoreLocalize(sc, res)
	if s.RecallAt5 != 0 || s.MRR != 0 || s.Found != 0 {
		t.Fatalf("a total miss must score 0 across the board, got %+v", s)
	}
}

// Anti-overfit §14.2 #2: every bench must cite its external comparison.
func TestRenderLocalize_CitesAntares(t *testing.T) {
	out := RenderLocalize([]LocalizeScore{{Name: "x", Total: 1}})
	if !strings.Contains(out, "Antares") {
		t.Fatalf("localization scorecard must cite the Antares benchmark, got:\n%s", out)
	}
}

// Anti-overfit §14.2 #1: the scoring logic must be fixture-agnostic — it may not contain sink tokens or
// fixture answers, so it can't secretly pattern-match its way to a good score. We scope the check to the
// code ABOVE the fixture definitions (the scoring functions).
func TestScoringCodeIsFixtureAgnostic(t *testing.T) {
	src, err := os.ReadFile("localize.go")
	if err != nil {
		t.Fatal(err)
	}
	scoring := string(src)
	if i := strings.Index(scoring, "func LocalizeScenarios"); i >= 0 {
		scoring = scoring[:i]
	}
	for _, banned := range []string{"pickle", "innerhtml", "exec.command", "SELECT ", "requests.get", "CWE-89", "CWE-79"} {
		if strings.Contains(strings.ToLower(scoring), strings.ToLower(banned)) {
			t.Fatalf("scoring code leaks fixture-specific token %q — recall could overfit", banned)
		}
	}
}

func TestRenderLocalizeAblation(t *testing.T) {
	base := []LocalizeScore{{RecallAt1: 0.5, RecallAt3: 0.8, MRR: 0.6}}
	agent := []LocalizeScore{{RecallAt1: 0.7, RecallAt3: 0.9, MRR: 0.75}}
	out := RenderLocalizeAblation(base, agent)
	if !strings.Contains(out, "Δ +0.20") {
		t.Fatalf("ablation should report the recall@1 lift, got:\n%s", out)
	}
}
