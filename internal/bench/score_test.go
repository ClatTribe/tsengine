package bench

import (
	"testing"

	"github.com/ClatTribe/tsengine/pkg/types"
)

func scan(raw, enriched []types.Finding) *types.Scan {
	return &types.Scan{FindingsRaw: raw, FindingsEnriched: enriched}
}

func rawF(rule string) types.Finding { return types.Finding{RuleID: rule} }

func enrichedF(rule string, annotate bool) types.Finding {
	f := types.Finding{RuleID: rule}
	if annotate {
		f.SurfacePriority = &types.SurfacePriority{Score: 50}
	}
	return f
}

func TestScoreScan_FullRecall(t *testing.T) {
	f := &Fixture{
		Name: "x", Metric: MetricMustFindRecall, PassRecall: 1.0,
		MustFind: []string{"CVE-2020-27350", "CVE-2019-3462"},
	}
	sc := ScoreScan(f, scan([]types.Finding{
		rawF("trivy::CVE-2020-27350"),
		rawF("trivy::CVE-2019-3462"),
		rawF("trivy::CVE-2099-0000"),
	}, nil))
	if sc.DetectionRecall != 1.0 {
		t.Errorf("recall: got %.2f, want 1.0", sc.DetectionRecall)
	}
	if !sc.Pass {
		t.Errorf("should pass: %s", sc.FailReason)
	}
}

func TestScoreScan_PartialRecallFails(t *testing.T) {
	f := &Fixture{
		Name: "x", Metric: MetricMustFindRecall, PassRecall: 1.0,
		MustFind: []string{"CVE-2020-27350", "CVE-2019-3462"},
	}
	sc := ScoreScan(f, scan([]types.Finding{rawF("trivy::CVE-2020-27350")}, nil))
	if sc.DetectionRecall != 0.5 {
		t.Errorf("recall: got %.2f, want 0.5", sc.DetectionRecall)
	}
	if sc.Pass {
		t.Error("should fail on partial recall")
	}
	if len(sc.Missed) != 1 || sc.Missed[0] != "CVE-2019-3462" {
		t.Errorf("missed: %v", sc.Missed)
	}
}

func TestScoreScan_FalsePositiveFails(t *testing.T) {
	f := &Fixture{
		Name: "x", Metric: MetricFPRate, PassRecall: 1.0,
		MustNotFind: []string{"CVE-2099-0000"},
	}
	sc := ScoreScan(f, scan([]types.Finding{rawF("trivy::CVE-2099-0000")}, nil))
	if sc.Pass {
		t.Error("should fail when a must_not_find appears")
	}
	if len(sc.FalsePositives) != 1 {
		t.Errorf("false positives: %v", sc.FalsePositives)
	}
}

func TestScoreScan_BenignMaxFindings(t *testing.T) {
	zero := 0
	f := &Fixture{Name: "x", Metric: MetricFPRate, MaxFindings: &zero}
	sc := ScoreScan(f, scan([]types.Finding{rawF("a"), rawF("b")}, nil))
	if sc.Pass {
		t.Error("benign fixture (max 0) should fail with 2 findings")
	}
	// And passes with zero findings.
	sc = ScoreScan(f, scan(nil, nil))
	if !sc.Pass {
		t.Errorf("benign fixture should pass with 0 findings: %s", sc.FailReason)
	}
}

func TestScoreScan_EnrichmentCoverage(t *testing.T) {
	f := &Fixture{Name: "x", Metric: MetricMustFindRecall}
	// 2 of 3 enriched findings carry annotations → 0.66.
	sc := ScoreScan(f, scan(
		[]types.Finding{rawF("a")},
		[]types.Finding{enrichedF("a", true), enrichedF("b", true), enrichedF("c", false)},
	))
	if sc.EnrichmentCov < 0.66 || sc.EnrichmentCov > 0.67 {
		t.Errorf("enrichment coverage: got %.4f, want ~0.667", sc.EnrichmentCov)
	}
}

func TestScoreScan_EnrichmentZeroWhenDisabled(t *testing.T) {
	// Simulates TSENGINE_L15_DISABLED=1: enriched findings carry no
	// annotations → coverage 0 (the ablation floor).
	f := &Fixture{Name: "x", Metric: MetricMustFindRecall}
	sc := ScoreScan(f, scan(
		[]types.Finding{rawF("a")},
		[]types.Finding{enrichedF("a", false)},
	))
	if sc.EnrichmentCov != 0 {
		t.Errorf("disabled enrichment coverage should be 0; got %.4f", sc.EnrichmentCov)
	}
}

func TestScoreScan_NoMustFindIsTriviallyComplete(t *testing.T) {
	f := &Fixture{Name: "x", Metric: MetricFPRate}
	sc := ScoreScan(f, scan(nil, nil))
	if sc.DetectionRecall != 1.0 || !sc.Pass {
		t.Errorf("empty must_find should be trivially complete: %+v", sc)
	}
}
