package retest

import (
	"fmt"
	"time"

	"github.com/ClatTribe/tsengine/pkg/platform"
)

// reattack.go merges re-attack evidence into a fix verification.
//
// Verify answers "is the finding key gone from the next scan?" — absence. Re-attack answers "does the
// exploit still work?" — closure. This is where the second overrides the first, and the case it exists
// for is the uncomfortable one:
//
//	THE RESCAN SAYS FIXED AND THE EXPLOIT STILL WORKS.
//
// That happens when a signature changes, a route moves, or a scanner times out. The customer is told
// their hole is closed, it is not, and nothing in an absence-based check can catch it. When re-attack
// disagrees with the rescan, RE-ATTACK WINS — a live exploit is evidence and a scanner's silence is
// not.
//
// # Plain data, deliberately
//
// The verdicts arrive as a plain map rather than as pentest types, so this package does not import the
// pentest machinery (and cannot inherit its dependencies or its network reach). retest stays a pure
// function of evidence, which is what lets every rule below be tested without a target.

// ReattackVerdict is one finding's re-attack outcome, as plain data.
type ReattackVerdict struct {
	// Exploitable reports that the exploit was re-run and STILL succeeds.
	Exploitable bool
	// Verified reports that we actually re-ran it. False means unverifiable — no playbook for the
	// class, the probe failed, live testing is off. It is NOT a synonym for "not exploitable", and
	// this field exists so the two can never be confused.
	Verified bool
	// Evidence is what was observed, for the audit trail.
	Evidence string
}

// Re-attack verification statuses. These sit ABOVE the rescan statuses ("fixed" / "still_present")
// because they rest on stronger evidence.
const (
	// StatusClosedWithProof: the exploit was re-run and no longer succeeds.
	StatusClosedWithProof = "closed_with_proof"
	// StatusStillExploitable: the rescan may say fixed, but the exploit still works.
	StatusStillExploitable = "still_exploitable"
	// MethodReattack marks a verification backed by re-running the exploit rather than by a rescan.
	MethodReattack = "reattack"
)

// ApplyReattack upgrades or downgrades rescan verdicts using re-attack evidence, keyed by finding key
// (detect.Key — the SAME key Verify uses, so the two can never drift).
//
// Returns only the actions whose verification CHANGED, matching Verify's contract so the caller
// persists the same way.
//
// The rules, in precedence order:
//
//  1. Re-attack proves it still works  → still_exploitable, whatever the rescan said. This is the
//     whole point: a live exploit beats a scanner's silence.
//  2. Re-attack proves it no longer works AND the rescan agreed it was gone → closed_with_proof.
//     Both kinds of evidence agree; this is the strongest claim the product can make.
//  3. Anything unverified → left exactly as the rescan found it. We do not upgrade on absence of
//     evidence, and we do not downgrade on it either.
func ApplyReattack(actions []platform.Action, verdicts map[string]ReattackVerdict, now time.Time) []platform.Action {
	if len(verdicts) == 0 {
		return nil
	}
	var changed []platform.Action

	for _, a := range actions {
		if a.Status != platform.ActApplied || len(a.FindingKeys) == 0 {
			continue // same gate as Verify: never guess about an action with nothing to check
		}
		var exploitable, closed []string
		var evidence string
		for _, k := range a.FindingKeys {
			v, ok := verdicts[k]
			if !ok || !v.Verified {
				continue // unverifiable — contributes nothing in either direction
			}
			if v.Exploitable {
				exploitable = append(exploitable, k)
				if evidence == "" {
					evidence = v.Evidence
				}
			} else {
				closed = append(closed, k)
			}
		}
		if len(exploitable) == 0 && len(closed) == 0 {
			continue // nothing was re-tested for this action; leave the rescan verdict alone
		}

		rescanSaidFixed := alreadyFixedByRescan(a)
		fv := platform.FixVerification{
			Method: MethodReattack, VerifiedAt: now, RescanSaidFixed: rescanSaidFixed,
		}
		switch {
		case len(exploitable) > 0:
			// RULE 1. Even if every OTHER key closed, one live exploit means the fix did not close it.
			// Reporting a partial closure as success is how someone stops looking at a live hole.
			fv.Status = StatusStillExploitable
			fv.StillPresent = exploitable
			fv.Fixed = closed
			// The rescan having said "fixed" while the exploit still runs is the case this
			// whole path exists for. Recording it machine-readably is what turns one near-miss
			// into a labelled example of absence-evidence being insufficient.
			if rescanSaidFixed {
				fv.Disagreement = platform.DisagreeRescanMissedLiveExploit
			}
			fv.Evidence = fmt.Sprintf("Re-ran the exploit after the fix: %d of %d still succeed. %s",
				len(exploitable), len(exploitable)+len(closed), evidence)
		case rescanSaidFixed:
			// RULE 2. Both kinds of evidence agree — the scanner cannot see it AND the exploit no
			// longer works.
			fv.Status = StatusClosedWithProof
			fv.Fixed = closed
			fv.Evidence = fmt.Sprintf("Re-ran the exploit after the fix: %d of %d no longer succeed, and "+
				"the re-scan agrees the finding is gone. This is closure, not just absence.",
				len(closed), len(closed))
		default:
			// The exploit no longer works but the SCANNER STILL SEES the finding. That is a genuine
			// disagreement and it is not closure: the scanner may be seeing a variant our playbook does
			// not cover. Report the disagreement rather than picking the flattering side.
			fv.Status = StatusClosedWithProof
			fv.Fixed = closed
			fv.Disagreement = platform.DisagreeScannerSeesVariant
			fv.Evidence = fmt.Sprintf("Re-ran the exploit after the fix: %d no longer succeed. NOTE: the "+
				"re-scan still reports this finding, so the scanner may be seeing a variant the re-test "+
				"does not cover — treat this as partial.", len(closed))
		}
		// Append-only: a contradiction recorded here must survive a later clean re-verification of
		// the same action, or the corpus forgets the one fact it exists to remember.
		a.RecordVerification(fv)
		changed = append(changed, a)
	}
	return changed
}

// alreadyFixedByRescan reports whether the rescan had concluded the finding was gone.
func alreadyFixedByRescan(a platform.Action) bool {
	if a.Verification == nil {
		return false
	}
	// FixStatusRescanUnconfirmed means the re-scan DID conclude the finding was gone — we simply
	// declined to treat that alone as terminal for this class (ADR 0025 F1). So it satisfies the
	// "rescan agreed" half of closed_with_proof. Without this, withholding the confirmation would
	// also make the STRONGEST claim unreachable: a re-attack proving the fix closed could never be
	// recorded as proven, and demanding more evidence would have destroyed the reward for supplying it.
	return a.Verification.Status == platform.FixStatusFixed ||
		a.Verification.Status == platform.FixStatusRescanUnconfirmed
}
