package cloudengine

import "testing"

// TestHoldout_GroundTruthIsIndependent asserts the held-out generator's labels
// are computed by an oracle the engine does NOT run (cloudiam eval over trust
// policies + permission boundaries). GenerateHoldout returns an error if any
// template's independent check fails to actually block — so a successful build is
// proof the inert labels are real, not asserted.
func TestHoldout_GroundTruthIsIndependent(t *testing.T) {
	scn, err := GenerateHoldout(1, 2)
	if err != nil {
		t.Fatalf("held-out generator rejected its own templates (independent check failed): %v", err)
	}
	var real, known, held int
	for _, p := range scn.Planted {
		switch p.Class {
		case classRealReachable:
			real++
		case classInertKnown:
			known++
		case classInertHeldOut:
			held++
		}
	}
	if real == 0 || known == 0 || held == 0 {
		t.Fatalf("held-out scenario must mix all three classes; got real=%d known=%d held=%d", real, known, held)
	}
}

// TestHoldout_ExposesOverfitGap is the anti-overfit guard. The engine aces the
// in-distribution bench (~100%) but that is circular. This held-out set labels
// truth INDEPENDENTLY, and the engine must:
//   - find the genuinely-reachable paths (recall 1.0), and
//   - downgrade the inert shapes it ENCODES (known FP-reduction 1.0), AND
//   - downgrade the inert shapes it does NOT encode (held-out FP-reduction 1.0).
//
// THIS TEST WAS A TRIPWIRE ON A KNOWN GAP AND IS NOW A GUARD ON THE FIX. It used to
// assert held-out FP-reduction < 1.0 and false paths > 0, documenting a 50-point overfit
// gap whose named cause was iam_inline_policy_allows_privilege_escalation: ingest built
// privesc edges from ATTACHED policies alone, so a role whose permission boundary
// blocked the escalation still got a path to admin. cloudgraph.AddPrivescEdgesWithBoundaries
// now asks cloudiam for the effective permission (attached ∧ boundary), and the gap is 0.
//
// Flipped rather than deleted, because the assertions that matter are the ones that
// would catch the fix REGRESSING — and because a benchmark whose failing case is removed
// stops being able to fail.
//
// Read the caveats in holdout.go's plantHeldOutBoundary before quoting this as a product
// claim: the evaluator is fixed, but no production ingest path generates policy-derived
// privesc edges yet, and awsfetch does not read boundaries.
func TestHoldout_NoOverfitGap(t *testing.T) {
	agg, n, err := RunHoldout(1, 10, 2, 0)
	if err != nil {
		t.Fatalf("RunHoldout: %v", err)
	}
	if n != 10 {
		t.Fatalf("expected 10 accounts, got %d", n)
	}
	// Controls: the engine must handle in-distribution shapes perfectly, else the
	// held-out result below would be ambiguous (could be a general regression).
	if agg.PathRecall != 1.0 {
		t.Errorf("recall on genuinely-reachable paths = %.4f, want 1.0", agg.PathRecall)
	}
	if agg.KnownFPRed != 1.0 {
		t.Errorf("known-shape FP-reduction = %.4f, want 1.0 (control)", agg.KnownFPRed)
	}
	// The probe, now a guard. A regression here means ingest has gone back to
	// over-approximating, and an over-approximated path is a false one: it sends someone
	// to sever a route that was never open while the real one stays open.
	if agg.HeldOutFPRed != 1.0 {
		t.Errorf("held-out FP-reduction = %.4f, want 1.0 — the boundary/trust fix has regressed; "+
			"falsely-reported checks: %v", agg.HeldOutFPRed, agg.HeldOutMissed)
	}
	if agg.FalsePaths != 0 {
		t.Errorf("held-out false attack paths = %d, want 0 — a false path is worse than a missed one",
			agg.FalsePaths)
	}
	// Recall is asserted above, but state the reason here too: a "fix" that closed the
	// gap by dropping genuinely-reachable paths would score perfectly on FP-reduction and
	// be strictly worse than the bug.
	if agg.PathRecall < 1.0 {
		t.Errorf("recall fell to %.4f — the gap must not be closed by dropping real paths", agg.PathRecall)
	}
}
