package bench

import (
	"fmt"
	"strings"
)

// remediation.go — the FIND-AND-FIX completeness of the L2 agent. Recall/ranking measure whether the
// agent FINDS the attack paths; but the AI Security Engineer's job doesn't end at detection — it must
// propose a remediation that PROVABLY closes each path. This is the defensive twin of the offensive
// verified_rate (a PoC-proven exploit): a cloudiam-VERIFIED fix (the evaluator confirms the proposed
// policy cuts the edge) is the defensive "proven", not a plausible-looking suggestion.
//
// Closes the last L2-evaluation completeness gap named in the accuracy+completeness review: the benchmark
// scored what the agent found, not whether it produced a WORKING fix for it.

// RemediationScore grades an agent's remediation over the issues it confirmed.
type RemediationScore struct {
	Confirmed    int     `json:"confirmed"`     // attack paths the agent confirmed (the denominator)
	Proposed     int     `json:"proposed"`      // of those, how many it proposed a fix for
	Verified     int     `json:"verified"`      // of those, how many fixes the evaluator VERIFIED cut the path
	Coverage     float64 `json:"coverage"`      // Proposed / Confirmed — did it try to fix everything it found?
	VerifiedRate float64 `json:"verified_rate"` // Verified / Confirmed — the "found AND provably closed" rate
}

// ComputeRemediationScore grades remediation from the confirmed / proposed / verified counts. A verified
// fix is one the deterministic evaluator (cloudiam) confirmed cuts the recorded path — never the agent's
// own say-so (§10). Counts are clamped so a noisy input can't report more verified than proposed/confirmed.
func ComputeRemediationScore(confirmed, proposed, verified int) RemediationScore {
	if proposed > confirmed {
		proposed = confirmed
	}
	if verified > proposed {
		verified = proposed
	}
	r := RemediationScore{Confirmed: confirmed, Proposed: proposed, Verified: verified}
	if confirmed > 0 {
		r.Coverage = float64(proposed) / float64(confirmed)
		r.VerifiedRate = float64(verified) / float64(confirmed)
	} else {
		// nothing confirmed → nothing to remediate; vacuously complete (recall carries the verdict elsewhere).
		r.Coverage, r.VerifiedRate = 1, 1
	}
	return r
}

// FullyRemediated reports whether every confirmed path got a verified fix — the closed-loop ideal.
func (r RemediationScore) FullyRemediated() bool {
	return r.Confirmed == 0 || r.Verified == r.Confirmed
}

// Verdict is the one-line remediation read.
func (r RemediationScore) Verdict() string {
	switch {
	case r.Confirmed == 0:
		return "no confirmed paths to remediate"
	case r.Verified == r.Confirmed:
		return fmt.Sprintf("every path closed with a VERIFIED fix (%d/%d)", r.Verified, r.Confirmed)
	case r.Verified > 0:
		return fmt.Sprintf("%d/%d paths closed with a verified fix, %d proposed-but-unverified, %d left open",
			r.Verified, r.Confirmed, r.Proposed-r.Verified, r.Confirmed-r.Proposed)
	case r.Proposed > 0:
		return fmt.Sprintf("proposed fixes for %d/%d paths but NONE verified to cut the path (unproven remediation)", r.Proposed, r.Confirmed)
	default:
		return fmt.Sprintf("found %d path(s) but proposed NO fix — detection without remediation", r.Confirmed)
	}
}

// RenderRemediationScore is the operator-facing remediation line.
func RenderRemediationScore(r RemediationScore) string {
	var b strings.Builder
	fmt.Fprintf(&b, "remediation: coverage %.0f%% (%d/%d fixed), verified_rate %.0f%% (%d/%d proven to cut the path) — %s\n",
		r.Coverage*100, r.Proposed, r.Confirmed, r.VerifiedRate*100, r.Verified, r.Confirmed, r.Verdict())
	return b.String()
}
