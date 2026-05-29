package bench

import (
	"math"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/pkg/types"
)

func wf(rule, cwe, endpoint string) types.Finding {
	return types.Finding{RuleID: rule, Tool: "t", CWE: []string{cwe}, Endpoint: endpoint}
}

func TestScoreWavsep_ConfusionMatrixAndYouden(t *testing.T) {
	cases := []WavsepCase{
		{URL: "sqli-vuln-1", Category: "sqli", Vulnerable: true},
		{URL: "sqli-vuln-2", Category: "sqli", Vulnerable: true},
		{URL: "sqli-fp-1", Category: "sqli", Vulnerable: false},
		{URL: "xss-vuln-1", Category: "xss", Vulnerable: true},
	}
	scan := &types.Scan{FindingsRaw: []types.Finding{
		wf("sqlmap::sqli", "CWE-89", "https://t/sqli-vuln-1?id=1"), // TP
		// sqli-vuln-2 not flagged → FN
		wf("nuclei::sqli", "CWE-89", "https://t/sqli-fp-1?id=1"), // FP (flagged a non-vuln)
		wf("dalfox::xss", "CWE-79", "https://t/xss-vuln-1?q=1"),  // TP
	}}
	rep := ScoreWavsep(cases, scan)

	sqli := rep.PerCategory["sqli"]
	if sqli.TP != 1 || sqli.FN != 1 || sqli.FP != 1 || sqli.TN != 0 {
		t.Errorf("sqli matrix: %+v (want TP1 FN1 FP1 TN0)", sqli)
	}
	// sqli Youden = TPR(1/2=0.5) − FPR(1/1=1.0) = -0.5
	if math.Abs(sqli.Youden()-(-0.5)) > 1e-9 {
		t.Errorf("sqli Youden: got %.3f, want -0.5", sqli.Youden())
	}
	xss := rep.PerCategory["xss"]
	if xss.TP != 1 || xss.Youden() != 1.0 {
		t.Errorf("xss: %+v Youden=%.2f (want TP1 Youden1.0)", xss, xss.Youden())
	}
	// Overall aggregates.
	if rep.Overall.TP != 2 || rep.Overall.FP != 1 || rep.Overall.FN != 1 {
		t.Errorf("overall: %+v", rep.Overall)
	}
}

func TestScoreWavsep_CategoryMustMatch(t *testing.T) {
	// A finding in the WRONG category doesn't flag the case.
	cases := []WavsepCase{{URL: "case-1", Category: "sqli", Vulnerable: true}}
	scan := &types.Scan{FindingsRaw: []types.Finding{
		wf("dalfox::xss", "CWE-79", "https://t/case-1?q=1"), // xss finding, sqli case → not flagged
	}}
	rep := ScoreWavsep(cases, scan)
	if rep.PerCategory["sqli"].TP != 0 || rep.PerCategory["sqli"].FN != 1 {
		t.Errorf("cross-category match should NOT count as TP: %+v", rep.PerCategory["sqli"])
	}
}

func TestLoadWavsepCases_SampleCSV(t *testing.T) {
	cases, err := LoadWavsepCases(filepath.Join("..", "..", "fixtures", "web", "wavsep", "expected-cases.sample.csv"))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(cases) != 5 {
		t.Fatalf("got %d cases; want 5 (header + comments skipped)", len(cases))
	}
	// First row: sqli vuln.
	if cases[0].Category != "sqli" || !cases[0].Vulnerable {
		t.Errorf("case[0]: %+v", cases[0])
	}
	// FP rows parsed as not-vulnerable.
	if cases[1].Vulnerable {
		t.Errorf("case[1] should be a false-positive case: %+v", cases[1])
	}
}

func TestRenderWavsep_CitesCompetitors(t *testing.T) {
	rep := ScoreWavsep([]WavsepCase{{URL: "a", Category: "sqli", Vulnerable: true}},
		&types.Scan{FindingsRaw: []types.Finding{wf("sqlmap::sqli", "CWE-89", "https://t/a?id=1")}})
	out := RenderWavsep(rep)
	if !strings.Contains(out, "competitors:") || !strings.Contains(out, "Acunetix") {
		t.Errorf("WAVSEP report must cite competitors:\n%s", out)
	}
	if !strings.Contains(out, "overall Youden") {
		t.Errorf("report missing overall Youden:\n%s", out)
	}
}
