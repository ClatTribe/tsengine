package tenanteval

import "fmt"

// route.go: evidence for MOVING a role to a different model, from the customer's own graded cases.
//
// The thesis that a cheaper model can do much of this work is only safe where something shows it on
// THIS estate. A vendor benchmark is not that, and neither is "it found 15 where the frontier found 17".
// The evidence here is the same suite the tenant's current model was graded on, re-asked of the
// candidate: same cases, same answer key, one number each. Three outcomes, never collapsed:
//
//   - matches   — the candidate agreed with the customer at least as often as the current model;
//   - worse     — it agreed less often, so switching would trade quality for cost on the customer's own
//                 judgements, and the switch must be acknowledged rather than made silently;
//   - unmeasured — no trial on this suite, too few cases to mean anything, or nothing to compare with.
//                 Unmeasured is NOT a pass; it is reported as itself so nobody reads silence as "safe".

// ArmCandidate is a model graded on the suite BEFORE it is assigned — a trial, kept apart from the
// assigned model's history so a trial can never move that model's trend.
const ArmCandidate = "candidate"

// MinRouteCases is the smallest suite a routing decision may rest on. Above the 5 that makes a score
// worth showing, because a score that informs a person and a score that changes which model runs are
// different bars.
const MinRouteCases = 10

// RouteEvidence is the verdict on moving to a candidate model.
type RouteEvidence struct {
	Status    string `json:"status"` // matches | worse | unmeasured
	Reason    string `json:"reason"`
	Incumbent *Run   `json:"incumbent,omitempty"`
	Candidate *Run   `json:"candidate,omitempty"`
}

const (
	RouteMatches    = "matches"
	RouteWorse      = "worse"
	RouteUnmeasured = "unmeasured"
)

// latest returns the most recent run satisfying keep. RanAt is RFC3339Nano, which sorts as written.
func latest(runs []Run, keep func(Run) bool) *Run {
	var best *Run
	for i := range runs {
		if keep(runs[i]) && (best == nil || runs[i].RanAt > best.RanAt) {
			r := runs[i]
			best = &r
		}
	}
	return best
}

// RouteVerdict compares the candidate's latest trial with the assigned model's latest score, on the
// suite the tenant has NOW. A run on an older suite is not evidence about this one — the cases changed.
func RouteVerdict(runs []Run, candidate, suiteHash string) RouteEvidence {
	cand := latest(runs, func(r Run) bool {
		return r.Arm == ArmCandidate && r.Model == candidate && r.SuiteHash == suiteHash
	})
	inc := latest(runs, func(r Run) bool {
		return NormalizeArm(r.Arm) == ArmModel && r.SuiteHash == suiteHash
	})
	ev := RouteEvidence{Status: RouteUnmeasured, Incumbent: inc, Candidate: cand}
	switch {
	case cand == nil:
		ev.Reason = fmt.Sprintf("%s has not been tried on your graded cases, so nothing shows it is as good as the model you have.", candidate)
	case cand.Cases < MinRouteCases:
		ev.Reason = fmt.Sprintf("Only %d graded case(s); a routing decision needs at least %d, so this is not evidence either way.", cand.Cases, MinRouteCases)
	case inc == nil:
		ev.Reason = "Your current model has not been graded on these cases, so there is nothing to compare the trial with. Run the eval on your current model first."
	case cand.Passed*inc.Cases >= inc.Passed*cand.Cases:
		ev.Status = RouteMatches
		ev.Reason = fmt.Sprintf("%s agreed with your decisions on %d of %d cases; %s on %d of %d.",
			candidate, cand.Passed, cand.Cases, nonEmpty(inc.Model, "your current model"), inc.Passed, inc.Cases)
	default:
		ev.Status = RouteWorse
		ev.Reason = fmt.Sprintf("%s agreed with your decisions on %d of %d cases, below %s on %d of %d. Switching trades quality on your own cases for cost.",
			candidate, cand.Passed, cand.Cases, nonEmpty(inc.Model, "your current model"), inc.Passed, inc.Cases)
	}
	return ev
}

func nonEmpty(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}
