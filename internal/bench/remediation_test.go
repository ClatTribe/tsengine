package bench

import (
	"strings"
	"testing"
)

func TestRemediationScore(t *testing.T) {
	// the closed loop: found 2, fixed 2, both verified → fully remediated.
	full := ComputeRemediationScore(2, 2, 2)
	if !full.FullyRemediated() || full.VerifiedRate != 1 || full.Coverage != 1 {
		t.Errorf("2 found / 2 verified fixes is fully remediated, got %+v", full)
	}
	if !strings.Contains(full.Verdict(), "every path closed with a VERIFIED fix") {
		t.Errorf("verdict should announce the closed loop, got %q", full.Verdict())
	}

	// proposed but UNVERIFIED — plausible fixes that aren't proven to cut the path don't count (§10).
	unver := ComputeRemediationScore(2, 2, 0)
	if unver.FullyRemediated() || unver.VerifiedRate != 0 {
		t.Errorf("unverified fixes are not remediation, got %+v", unver)
	}
	if !strings.Contains(unver.Verdict(), "NONE verified") {
		t.Errorf("verdict should flag unproven remediation, got %q", unver.Verdict())
	}

	// detection WITHOUT remediation — found paths, proposed no fix.
	none := ComputeRemediationScore(3, 0, 0)
	if none.Coverage != 0 || !strings.Contains(none.Verdict(), "proposed NO fix") {
		t.Errorf("found-but-not-fixed should be flagged, got %+v / %q", none, none.Verdict())
	}

	// partial: 3 found, 2 fixed+verified, 1 open.
	part := ComputeRemediationScore(3, 2, 2)
	if part.FullyRemediated() || part.Verified != 2 {
		t.Errorf("a partial remediation is not fully remediated, got %+v", part)
	}
	if part.VerifiedRate < 0.66 || part.VerifiedRate > 0.67 {
		t.Errorf("verified_rate should be ~2/3, got %v", part.VerifiedRate)
	}

	// noisy input: more verified than proposed is clamped (evaluator can't verify a fix that wasn't made).
	clamp := ComputeRemediationScore(2, 1, 5)
	if clamp.Verified != 1 || clamp.Proposed != 1 {
		t.Errorf("verified must be clamped to proposed, got %+v", clamp)
	}

	// vacuous: nothing confirmed → nothing to remediate.
	if v := ComputeRemediationScore(0, 0, 0); !v.FullyRemediated() {
		t.Error("no confirmed paths is vacuously fully-remediated")
	}
}
