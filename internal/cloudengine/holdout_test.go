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
//   - downgrade the inert shapes it ENCODES (known FP-reduction 1.0),
//
// while it currently FAILS to downgrade inert shapes it does NOT encode
// (held-out FP-reduction < 1.0, false paths > 0). That gap is the honest overfit
// measure.
//
// WHEN THE ENGINE IS FIXED (trust-policy + permission-boundary aware ingest), the
// held-out FP-reduction rises to 1.0 and false paths drop to 0 — at which point
// flip the two `< 1.0` / `> 0` assertions below to `== 1.0` / `== 0`. This test
// is intentionally a tripwire on a known, documented gap.
func TestHoldout_ExposesOverfitGap(t *testing.T) {
	agg, n, err := RunHoldout(1, 10, 2, 0)
	if err != nil {
		t.Fatalf("RunHoldout: %v", err)
	}
	if n != 10 {
		t.Fatalf("expected 10 accounts, got %d", n)
	}
	// Controls: the engine must handle in-distribution shapes perfectly, else the
	// held-out gap below would be ambiguous (could be a general regression).
	if agg.PathRecall != 1.0 {
		t.Errorf("recall on genuinely-reachable paths = %.4f, want 1.0", agg.PathRecall)
	}
	if agg.KnownFPRed != 1.0 {
		t.Errorf("known-shape FP-reduction = %.4f, want 1.0 (control)", agg.KnownFPRed)
	}
	// The probe: documents the current gap. Flip these when ingest learns trust
	// policies + permission boundaries.
	if agg.HeldOutFPRed >= 1.0 {
		t.Errorf("held-out FP-reduction = %.4f — if this is now 1.0 the gap is CLOSED; "+
			"update this test to assert == 1.0 and celebrate", agg.HeldOutFPRed)
	}
	if agg.FalsePaths == 0 {
		t.Errorf("expected held-out false paths > 0 (the documented gap); got 0 — " +
			"if the engine now handles trust/boundary, update this test")
	}
	if len(agg.HeldOutMissed) == 0 {
		t.Errorf("expected the report to name the false-positived prowler checks")
	}
}
