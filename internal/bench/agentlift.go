package bench

import (
	"fmt"
	"strings"
)

// agentlift.go — the measured AGENT LIFT over the (possibly bounded) deterministic substrate on a
// head-to-head run. This is the number the AI Cloud/Security Engineer benchmark exists to produce.
//
// On a DISCRIMINATING scenario (see CloudDiscriminationReport) the substrate runs at a bounded worklist
// budget and under-covers — that is EXPECTED and the point. The agent's value is how much of that headroom
// it RECOVERS via targeted tool-use (find_paths / blast_radius on the right nodes). Without this the run
// printed the engine's own "under budget" self-verdict ("FAIL / divergence") ABOVE the head-to-head, which
// read as an overall failure when it is actually the setup for the agent to shine. AgentLift makes the
// measured contribution front-and-center, and — critically — only trusts a lift when the agent invented
// NOTHING (grounding, §10): a higher recall bought with hallucinated paths is not a lift.

// AgentLift is the agent's measured contribution over the substrate on one head-to-head account.
type AgentLift struct {
	RealTotal   int     `json:"real_total"`
	EngineFound int     `json:"engine_found"` // paths the (bounded) substrate found
	AgentFound  int     `json:"agent_found"`  // paths the agent confirmed
	Invented    int     `json:"invented"`     // agent's false/hallucinated issues (must be 0 to trust the lift)
	LiftPaths   int     `json:"lift_paths"`   // AgentFound - EngineFound (negative = regression)
	LiftPct     float64 `json:"lift_pct"`     // lift as a fraction of the reachable set
	Grounded    bool    `json:"grounded"`     // Invented == 0
}

// ComputeAgentLift derives the lift from the engine's and agent's found-counts on the same account.
func ComputeAgentLift(realTotal, engineFound, agentFound, invented int) AgentLift {
	l := AgentLift{
		RealTotal: realTotal, EngineFound: engineFound, AgentFound: agentFound,
		Invented: invented, LiftPaths: agentFound - engineFound, Grounded: invented == 0,
	}
	if realTotal > 0 {
		l.LiftPct = float64(l.LiftPaths) / float64(realTotal)
	}
	return l
}

// Verdict is the human read of the lift. An ungrounded run (invented > 0) is never a lift regardless of
// recall; a positive lift is the win the benchmark measures; zero lift on a fully-covered account is a
// non-discriminating scenario (the substrate already had it); a negative lift is a regression.
func (l AgentLift) Verdict() string {
	switch {
	case !l.Grounded:
		return fmt.Sprintf("UNGROUNDED — the agent invented %d issue(s); a lift bought with hallucination does not count", l.Invented)
	case l.LiftPaths > 0:
		return fmt.Sprintf("AGENT LIFT +%d path(s) (%.0f%%) — recovered real, reachable paths the bounded substrate missed, invented 0", l.LiftPaths, l.LiftPct*100)
	case l.LiftPaths == 0 && l.AgentFound == l.RealTotal:
		return "no lift measurable — the substrate already covered every path (non-discriminating scenario; run --discrimination to pick one with headroom)"
	case l.LiftPaths == 0:
		return "no lift — the agent matched the substrate (both under-covered the same set)"
	default:
		return fmt.Sprintf("AGENT REGRESSION -%d path(s) — the agent found FEWER real paths than the substrate", -l.LiftPaths)
	}
}

// Lifted reports whether the agent added grounded value (recovered headroom without inventing anything).
func (l AgentLift) Lifted() bool { return l.Grounded && l.LiftPaths > 0 }

// RenderAgentLift is the head-to-head lift summary line(s).
func RenderAgentLift(l AgentLift) string {
	var b strings.Builder
	fmt.Fprintf(&b, "AGENT LIFT: substrate %d/%d → agent %d/%d  |  %s\n",
		l.EngineFound, l.RealTotal, l.AgentFound, l.RealTotal, l.Verdict())
	return b.String()
}
