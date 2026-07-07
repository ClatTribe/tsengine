package bench

import (
	"fmt"
	"strings"
)

// l2scorecard.go — the UNIFIED L2-agent evaluation: one graded scorecard that answers "how good is the
// AI Security Engineer (the L2 LLM agent)?" on ACCURACY and reports COMPLETENESS of the evaluation itself.
//
// The pieces existed but scattered: cloudagent.Score has recall + false issues + a BINARY pass; AgentLift
// has the lift over the substrate; CloudDiscriminationReport has the headroom. None answered, in one place,
// "did the agent do a good job, and did this run actually TEST the agent?". This does.
//
// Two axes, matching the two questions asked of any benchmark:
//
//   ACCURACY (did the agent perform well?) — a single graded Score in [0,1]:
//     - Recall: real attack paths the agent confirmed / total reachable.
//     - Grounding (§10): the agent invented NOTHING. This is DISQUALIFYING — a recall bought with
//       hallucinated paths scores 0, because a security engineer you can't trust is worse than useless.
//     - Precision: confirmed / (confirmed + invented) — the FP-control dimension.
//     Score = grounded ? recall : 0. So a great score REQUIRES both high recall AND zero hallucination.
//
//   COMPLETENESS (did this run actually evaluate the agent?) — the Discriminating flag:
//     - If the deterministic substrate already found every path at this run's budget, the agent had NO
//       headroom to prove itself: its "score" reflects the substrate, not the L2 agent. Such a run is an
//       INCOMPLETE evaluation and must be flagged, or you tune against a benchmark that isn't measuring
//       the thing you think it is (§14 anti-overfit). A run only fully evaluates L2 when the substrate
//       left real, recoverable headroom (see CloudDiscriminationReport / the sweep).

// L2Scorecard is the graded, completeness-aware evaluation of one L2 head-to-head run.
type L2Scorecard struct {
	RealTotal   int     `json:"real_total"`
	EngineFound int     `json:"engine_found"` // the (bounded) substrate — the floor
	AgentFound  int     `json:"agent_found"`  // the L2 agent
	Invented    int     `json:"invented"`     // hallucinated / false issues (disqualifying if > 0)
	Recall      float64 `json:"recall"`
	Precision   float64 `json:"precision"`
	LiftPaths   int     `json:"lift_paths"` // agent - substrate: grounded value the agent added
	Grounded    bool    `json:"grounded"`   // Invented == 0
	// Score is the single graded accuracy number in [0,1]: recall, but 0 if the agent hallucinated.
	Score float64 `json:"score"`
	// Discriminating is the COMPLETENESS flag: did the substrate leave headroom for the agent to prove
	// itself? If false, this run evaluated the substrate, not the agent — the score is uninformative.
	Discriminating bool `json:"discriminating"`
}

// ComputeL2Scorecard grades an L2 head-to-head run from the substrate's and agent's found-counts + the
// agent's invented count. Discrimination is derived: the substrate left headroom iff it found fewer than
// the reachable total.
func ComputeL2Scorecard(realTotal, engineFound, agentFound, invented int) L2Scorecard {
	sc := L2Scorecard{
		RealTotal: realTotal, EngineFound: engineFound, AgentFound: agentFound, Invented: invented,
		Grounded: invented == 0, LiftPaths: agentFound - engineFound,
		Discriminating: engineFound < realTotal, // the substrate under-covered → the run can measure L2's discovery
	}
	if realTotal > 0 {
		sc.Recall = float64(agentFound) / float64(realTotal)
	}
	if agentFound+invented > 0 {
		sc.Precision = float64(agentFound) / float64(agentFound+invented)
	} else {
		sc.Precision = 1
	}
	if sc.Grounded {
		sc.Score = sc.Recall
	} // else Score stays 0 — hallucination is disqualifying (§10)
	return sc
}

// Grade is the human bucket for the accuracy Score (only meaningful on a complete evaluation).
func (s L2Scorecard) Grade() string {
	switch {
	case !s.Grounded:
		return "DISQUALIFIED"
	case s.Score >= 0.9:
		return "STRONG"
	case s.Score >= 0.6:
		return "ADEQUATE"
	default:
		return "WEAK"
	}
}

// Verdict is the one-line read, leading with completeness (an incomplete run's grade is uninformative).
func (s L2Scorecard) Verdict() string {
	if !s.Grounded {
		return fmt.Sprintf("DISQUALIFIED — the agent invented %d issue(s); §10 makes a hallucinated finding worse than a miss", s.Invented)
	}
	if !s.Discriminating {
		return "INCOMPLETE EVALUATION — the substrate already found every path at this budget, so the agent had no headroom to prove itself; this score reflects the SUBSTRATE, not L2. Run the discrimination sweep and re-run on a scenario with headroom."
	}
	return fmt.Sprintf("L2 %s — recall %.0f%%, +%d grounded lift over the bounded substrate, invented 0", s.Grade(), s.Recall*100, s.LiftPaths)
}

// RenderL2Scorecard is the operator-facing evaluation block.
func RenderL2Scorecard(s L2Scorecard) string {
	var b strings.Builder
	fmt.Fprintf(&b, "=== L2 agent scorecard (accuracy + completeness) ===\n")
	fmt.Fprintf(&b, "accuracy:  recall %.0f%% (%d/%d)  precision %.0f%%  grounded %v  →  score %.2f (%s)\n",
		s.Recall*100, s.AgentFound, s.RealTotal, s.Precision*100, s.Grounded, s.Score, s.Grade())
	fmt.Fprintf(&b, "completeness: %s (substrate found %d/%d — %s)\n",
		map[bool]string{true: "DISCRIMINATING", false: "NON-DISCRIMINATING"}[s.Discriminating],
		s.EngineFound, s.RealTotal,
		map[bool]string{true: "the run measured the agent's discovery", false: "the run measured the substrate, not the agent"}[s.Discriminating])
	fmt.Fprintf(&b, "verdict: %s\n", s.Verdict())
	return b.String()
}
