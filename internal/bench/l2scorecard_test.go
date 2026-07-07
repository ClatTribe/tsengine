package bench

import (
	"strings"
	"testing"
)

func TestL2Scorecard(t *testing.T) {
	// the real measured run: bounded substrate 1/2, agent 2/2, invented 0 → a COMPLETE, STRONG evaluation.
	s := ComputeL2Scorecard(2, 1, 2, 0)
	if !s.Discriminating {
		t.Error("the substrate under-covered (1/2), so this run DOES evaluate the agent — must be discriminating")
	}
	if !s.Grounded || s.Score != 1.0 || s.Grade() != "STRONG" {
		t.Errorf("a grounded 2/2 recovery is a STRONG score of 1.0, got %+v grade=%s", s, s.Grade())
	}
	if !strings.Contains(s.Verdict(), "L2 STRONG") || !strings.Contains(s.Verdict(), "+1 grounded lift") {
		t.Errorf("verdict should announce a strong, complete evaluation, got %q", s.Verdict())
	}

	// COMPLETENESS: a run where the substrate already found everything (2/2) is a NON-discriminating,
	// INCOMPLETE evaluation — the score reflects the substrate, not the agent, even though recall is 100%.
	flat := ComputeL2Scorecard(2, 2, 2, 0)
	if flat.Discriminating {
		t.Error("a substrate that found everything leaves no headroom — the run does NOT evaluate the agent")
	}
	if !strings.Contains(flat.Verdict(), "INCOMPLETE EVALUATION") {
		t.Errorf("a non-discriminating run must be flagged INCOMPLETE (this is the accuracy trap), got %q", flat.Verdict())
	}

	// ACCURACY: hallucination is disqualifying — a 2/2 recall bought with an invented issue scores 0.
	halluc := ComputeL2Scorecard(2, 1, 2, 1)
	if halluc.Grounded || halluc.Score != 0 || halluc.Grade() != "DISQUALIFIED" {
		t.Errorf("an invented issue must disqualify (score 0), got %+v grade=%s", halluc, halluc.Grade())
	}
	if halluc.Precision != float64(2)/float64(3) {
		t.Errorf("precision should be 2/3 with one invented issue, got %v", halluc.Precision)
	}

	// a partial grounded recovery on a discriminating scenario grades ADEQUATE/WEAK by recall.
	weak := ComputeL2Scorecard(10, 2, 5, 0) // 5/10 = 0.5 → WEAK
	if weak.Grade() != "WEAK" || !weak.Discriminating {
		t.Errorf("a grounded 5/10 on a discriminating scenario is WEAK, got %+v grade=%s", weak, weak.Grade())
	}
	adq := ComputeL2Scorecard(10, 2, 7, 0) // 7/10 = 0.7 → ADEQUATE
	if adq.Grade() != "ADEQUATE" {
		t.Errorf("a grounded 7/10 is ADEQUATE, got grade=%s", adq.Grade())
	}
}
