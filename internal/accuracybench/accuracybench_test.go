package accuracybench

import (
	"strings"
	"testing"
)

func TestScorecard_AllCoresPerfect(t *testing.T) {
	scores := Run()
	t.Log("\n" + Render(scores))

	if len(scores) != 6 {
		t.Fatalf("expected all 6 deterministic cores in the scorecard, got %d", len(scores))
	}
	// The unified gate: every core measures recall=1.0 AND precision=1.0 over its labeled corpus.
	// One place that regresses if ANY core's accuracy slips — the capstone of the campaign.
	for _, s := range scores {
		if !s.Perfect() {
			t.Errorf("%s fell below the bar: recall=%.2f precision=%.2f", s.Core, s.Recall, s.Precision)
		}
		if s.Cases == 0 {
			t.Errorf("%s reported zero labeled cases — its corpus is empty?", s.Core)
		}
	}
}

func TestRender_Shape(t *testing.T) {
	out := Render(Run())
	for _, want := range []string{"scorecard", "RECALL", "PRECISION", "ALL CORES PASS"} {
		if !strings.Contains(out, want) {
			t.Errorf("rendered scorecard missing %q:\n%s", want, out)
		}
	}
}
