package bench

import (
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/pkg/types"
)

// These pin the guard against the run that produced them.
//
// An api/VAmPI scan was recorded as "detection recall: median=0.000 · verdict: FAIL ·
// MISSED: sqli" and very nearly reached SCOREBOARD.md as a capability result for a focus
// asset. The scan had printed partial=true. Re-run against the same target on the same
// image with a budget it could finish in, it found sqlmap::sqli and scored 1.000.
//
// Nothing was wrong with the engine. The clock ran out mid-sqlmap, and the scorer had no
// idea the run had been cut off — it read the short finding list as a detection result,
// exactly as it would have read a complete one.
func TestTruncatedScan_WithholdsTheVerdictADeadlineCouldFake(t *testing.T) {
	fx := &Fixture{Name: "api-vampi", Metric: "must_find_recall", MustFind: []string{"sqli"}, PassRecall: 1.0}
	truncated := &types.Scan{Partial: true, FindingsRaw: []types.Finding{{RuleID: "openapi_spec_ingest::spec-found"}}}

	s := ScoreScan(fx, truncated)
	if !s.Unmeasured {
		t.Fatal("a recall FAIL on a scan that hit its deadline was reported as a detection result. " +
			"The finding may simply not have landed yet — this is the bug that put a false " +
			"0.000 FAIL for VAmPI one commit away from the scoreboard.")
	}
	if s.Pass {
		t.Error("an unmeasured run must never read as a pass")
	}
	if !strings.Contains(s.UnmeasuredReason, "LOWER BOUND") {
		t.Errorf("the reason must say the number is a lower bound, got %q", s.UnmeasuredReason)
	}
}

// The other direction of the same rule: truncation can only REMOVE findings, so a recall
// PASS is sound even when cut short — it found what was required despite being cut off.
// Withholding this too would throw away real results.
func TestTruncatedScan_KeepsAPassItCouldNotHaveFaked(t *testing.T) {
	fx := &Fixture{Name: "api-vampi", Metric: "must_find_recall", MustFind: []string{"sqli"}, PassRecall: 1.0}
	scan := &types.Scan{Partial: true, FindingsRaw: []types.Finding{{RuleID: "sqlmap::sqli"}}}

	s := ScoreScan(fx, scan)
	if s.Unmeasured {
		t.Error("a truncated scan that STILL found the required finding is a sound pass — " +
			"truncation removes findings, it cannot invent them")
	}
	if !s.Pass {
		t.Error("want pass")
	}
}

// FP-control inverts: a truncated clean run proves nothing, because the alarm may not
// have landed yet. Same rule, opposite direction.
func TestTruncatedScan_WithholdsACleanFPControlResult(t *testing.T) {
	fx := &Fixture{Name: "alpine-clean", Metric: "fp_rate", MaxSeverity: types.SeverityHigh, PassRecall: 0}
	scan := &types.Scan{Partial: true, FindingsRaw: []types.Finding{{RuleID: "x::note", Severity: types.SeverityInfo}}}

	s := ScoreScan(fx, scan)
	if !s.Unmeasured {
		t.Fatal("a clean FP-control verdict on a truncated scan was reported as a pass — " +
			"a high-severity alarm may simply not have fired yet")
	}
	if s.Pass {
		t.Error("an unmeasured run must never read as a pass")
	}
}

// And a real FP on a truncated run IS a result: the alarm fired, and finishing the scan
// could only have added more.
func TestTruncatedScan_KeepsAFalsePositiveItReallySaw(t *testing.T) {
	fx := &Fixture{Name: "alpine-clean", Metric: "fp_rate", MaxSeverity: types.SeverityHigh, PassRecall: 0}
	scan := &types.Scan{Partial: true, FindingsRaw: []types.Finding{{RuleID: "x::boom", Severity: types.SeverityCritical}}}

	s := ScoreScan(fx, scan)
	if s.Unmeasured {
		t.Error("the alarm actually fired — finishing the scan could only have added more")
	}
	if s.Pass {
		t.Error("want fail")
	}
}

// A complete scan is unaffected in every direction.
func TestCompleteScan_IsNeverWithheld(t *testing.T) {
	fx := &Fixture{Name: "api-vampi", Metric: "must_find_recall", MustFind: []string{"sqli"}, PassRecall: 1.0}
	s := ScoreScan(fx, &types.Scan{Partial: false, FindingsRaw: nil})
	if s.Unmeasured {
		t.Error("a scan that ran to completion and found nothing is a real FAIL, not an unmeasured run")
	}
	if s.Pass {
		t.Error("want fail")
	}
}
