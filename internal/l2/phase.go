package l2

// Phase is the L2 workflow state — tsengine's OODA encoded as a phase
// state machine (strix's "checkpoints, not gates" model). Each phase
// exposes only the tools relevant to it: this keeps the catalog the LLM
// sees small (the ≤12 cap is per-phase reachable) and stops the model from
// e.g. calling finish_scan during triage (strix's 36× finish_scan
// rejection-loop class of bug).
//
// L2 phases are SHORTER than strix's pentest flow because L1 already did
// recon + detection. L2 starts from findings:
//
//	triage      → read + prioritize the L1 findings (OBSERVE)
//	investigate → probe / verify hypotheses, dispatch_l2_probe (ORIENT/ACT)
//	chain       → correlate findings into attack chains (ORIENT)
//	report      → emit reports + finish_scan (COMMIT)
type Phase string

const (
	PhaseTriage      Phase = "triage"
	PhaseInvestigate Phase = "investigate"
	PhaseChain       Phase = "chain"
	PhaseReport      Phase = "report"
)

// phaseOrder is the forward progression. advance_phase steps along it;
// the agent can't skip backwards.
var phaseOrder = []Phase{PhaseTriage, PhaseInvestigate, PhaseChain, PhaseReport}

// nextPhase returns the phase after p, or p if already terminal.
func nextPhase(p Phase) Phase {
	for i, ph := range phaseOrder {
		if ph == p && i+1 < len(phaseOrder) {
			return phaseOrder[i+1]
		}
	}
	return p
}

// phaseIndex is p's position in the progression (-1 if unknown).
func phaseIndex(p Phase) int {
	for i, ph := range phaseOrder {
		if ph == p {
			return i
		}
	}
	return -1
}

// allowedInPhase reports whether a tool whose allowed-phase set is `phases`
// may run in the current phase. An empty/zero allowed set means "all
// phases" (e.g. think). A tool allowed in phase X is also allowed in every
// LATER phase — later phases can still use earlier capabilities (read
// state, probe) — but not earlier ones (no finish_scan before report).
func allowedInPhase(toolPhases []Phase, current Phase) bool {
	if len(toolPhases) == 0 {
		return true
	}
	ci := phaseIndex(current)
	for _, p := range toolPhases {
		if pi := phaseIndex(p); pi >= 0 && ci >= pi {
			return true
		}
	}
	return false
}
