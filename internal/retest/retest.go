// Package retest is the fix-verification capability — the answer to the industry finding that
// most teams never confirm a fix actually worked ("60% don't retest after fixes; a fix that isn't
// verified is a fix you're taking on trust", State-of-AI-in-Pentesting KF#4).
//
// When a remediation Action is APPLIED, the engine re-tests it against the next authoritative scan
// and records a grounded platform.FixVerification on the action: "fixed" when every finding it
// claimed to resolve is provably absent from the fresh scan, "still_present" when any remain (the
// fix did not close them — reopen). This is the remediation-scoped twin of detect.Reconcile
// (which resolves INCIDENTS when their issue disappears); retest verifies the specific ACTION and
// surfaces an explicit, evidence-backed "verified fixed" state to the user + the evidence pack.
//
// Grounding (§10): the verdict is derived only from a real re-scan. An action carrying no finding
// keys is never guessed-at — it is simply left un-verified. "fixed" only when absence is proven.
package retest

import (
	"fmt"
	"time"

	"github.com/ClatTribe/tsengine/internal/detect"
	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// Keys returns the de-duplicated stable identities (rule_id|endpoint, via detect.Key — the SAME
// key fix-verification compares against, so the two can never drift) for a set of findings. Used
// to stamp an Action's FindingKeys at propose time.
func Keys(findings []types.Finding) []string {
	seen := map[string]bool{}
	var out []string
	for _, f := range findings {
		k := detect.Key(f)
		if !seen[k] {
			seen[k] = true
			out = append(out, k)
		}
	}
	return out
}

// KeysForIDs maps the given finding IDs to their stable keys using the supplied findings as the
// lookup — for stamping a BULK action (which carries FindingIDs) with its FindingKeys.
func KeysForIDs(ids []string, findings []types.Finding) []string {
	byID := make(map[string]types.Finding, len(findings))
	for _, f := range findings {
		byID[f.ID] = f
	}
	var picked []types.Finding
	for _, id := range ids {
		if f, ok := byID[id]; ok {
			picked = append(picked, f)
		}
	}
	return Keys(picked)
}

// Verify re-tests APPLIED remediations against the authoritative current scan output and returns
// ONLY the actions whose verification CHANGED (for the caller to persist + record into the ledger).
//
// For each applied action that carries finding keys and is not already terminally "fixed":
//   - every key absent from `current` → Status "fixed"   (the fix is confirmed)
//   - any key still present           → Status "still_present" (the fix did not close it — reopen)
//
// Idempotent: re-running with the same scan re-emits nothing (a verdict identical to the existing
// one is skipped). "fixed" is terminal — a vuln that REAPPEARS later is a regression that
// detect.Reconcile opens as a NEW incident, not a re-flip of the old fix's verification.
func Verify(actions []platform.Action, current []types.Finding, now time.Time) []platform.Action {
	present := make(map[string]bool, len(current))
	for _, f := range current {
		present[detect.Key(f)] = true
	}
	var changed []platform.Action
	for _, a := range actions {
		if a.Status != platform.ActApplied || len(a.FindingKeys) == 0 {
			continue // never guess: no applied fix / no keys → leave un-verified (§10)
		}
		if a.Verification != nil && a.Verification.Status == "fixed" {
			continue // terminal
		}
		var fixed, still []string
		for _, k := range a.FindingKeys {
			if present[k] {
				still = append(still, k)
			} else {
				fixed = append(fixed, k)
			}
		}
		status := "fixed"
		if len(still) > 0 {
			status = "still_present"
		}
		// Skip if the verdict is unchanged from what's already recorded (idempotent re-runs).
		if a.Verification != nil && a.Verification.Status == status &&
			len(a.Verification.StillPresent) == len(still) {
			continue
		}
		a.Verification = &platform.FixVerification{
			Status:       status,
			Method:       "rescan",
			VerifiedAt:   now,
			Fixed:        fixed,
			StillPresent: still,
			Evidence:     evidence(status, len(fixed), len(a.FindingKeys)),
		}
		changed = append(changed, a)
	}
	return changed
}

func evidence(status string, fixed, total int) string {
	if status == "fixed" {
		return fmt.Sprintf("%d of %d confirmed fixed in re-scan", fixed, total)
	}
	return fmt.Sprintf("%d of %d still present in re-scan — fix did not close them", total-fixed, total)
}
