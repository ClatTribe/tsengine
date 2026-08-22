package accuracybench

import "testing"

// The corpora must not SHRINK.
//
// TestScorecard_AllCoresPerfect already asserts every core is 1.00/1.00 and non-empty, so a
// regression in ACCURACY is caught. What it cannot catch is a corpus that shrinks: it checks only
// Cases != 0, so a core whose labeled set went from 34 to 2 still passes at a perfect 1.00 — a
// weaker claim wearing the same number. That is the vacuous-pass shape this codebase keeps fixing,
// where a rate rises as the evidence behind it disappears.
//
// Read the perfect column correctly either way: these corpora are ones WE wrote, so they measure
// whether the fixtures and the code agree, not whether the product works (§14.2.5). Two external
// keys put the same class of capability near two thirds (BishopFox IAM-Vulnerable 64.5%,
// RhinoSecurityLabs GCP 65.2%). This is regression detection, not evidence of efficacy. A core whose cases were deleted scores a perfect 1.00 over nothing,
// which is the same vacuous pass this codebase keeps having to fix elsewhere: a rate that rises as
// the evidence disappears.
func TestCorporaDidNotShrink(t *testing.T) {
	// Recorded 2026-08-22 from the live run.
	floors := map[string]int{
		"apiauthz (BOLA/BFLA/mass-assign)": 12,
		"identitythreat (ITDR rules)":      14,
		"operate (email-auth)":             9,
		"registrywatch (mutable-tag)":      23,
		"shadowit (sensitive-scope)":       34,
		"webauth (login-wall)":             15,
	}
	got := map[string]int{}
	for _, s := range Run() {
		got[s.Core] = s.Cases
	}
	for core, floor := range floors {
		n, ok := got[core]
		if !ok {
			t.Errorf("core %q disappeared from the scorecard entirely", core)
			continue
		}
		if n < floor {
			t.Errorf("%s: %d cases, down from %d — a perfect score over fewer cases is a weaker "+
				"claim, not a better one", core, n, floor)
		}
	}
}
