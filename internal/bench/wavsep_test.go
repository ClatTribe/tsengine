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

// The full WAVSEP corpus (ported from the WAVSEP project) must load
// cleanly: ~1,133 cases, the 4th `cwe` column ignored, and the
// `url_path` header row skipped (no junk "category" category).
func TestLoadWavsepCases_FullCorpus(t *testing.T) {
	cases, err := LoadWavsepCases(filepath.Join("..", "..", "fixtures", "web", "wavsep", "expected-cases.csv"))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(cases) != 1133 {
		t.Fatalf("got %d cases; want 1133 (header + comments skipped, 4th col ignored)", len(cases))
	}
	// The header row must not leak in as a bogus case.
	seen := map[string]int{}
	for _, c := range cases {
		seen[c.Category]++
		if c.Category == "category" || strings.HasPrefix(strings.ToLower(c.URL), "url") {
			t.Fatalf("header row leaked as a case: %+v", c)
		}
	}
	// Every category must map to a CWE the scorer understands, else the
	// ground truth and the CWE→category map have drifted.
	for cat := range seen {
		found := false
		for _, mapped := range cweToWavsepCategory {
			if mapped == cat {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("corpus category %q has no CWE mapping in cweToWavsepCategory", cat)
		}
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

// TestScoreWavsep_UnreachedCasesAreNotMisses pins the distinction between "we tested this and found
// nothing" and "we never went there".
//
// The corpus is 1,133 cases and TSENGINE_FANOUT_MAX_URLS defaults to 200, so a default run visits a
// fraction of it. Grading the rest as misses measured the cost guard and reported it as scanner
// recall — a number that would then sit next to Acunetix's 87% over the full corpus.
func TestScoreWavsep_UnreachedCasesAreNotMisses(t *testing.T) {
	cases := []WavsepCase{
		{URL: "/wavsep/a.jsp", Category: "sqli", Vulnerable: true}, // crawled + found
		{URL: "/wavsep/b.jsp", Category: "sqli", Vulnerable: true}, // crawled, missed → a real FN
		{URL: "/wavsep/z.jsp", Category: "sqli", Vulnerable: true}, // never crawled → excluded
	}
	scan := &types.Scan{
		DiscoveredSurface: []string{
			"http://host.docker.internal:8080/wavsep/a.jsp?p=1", // absolute + query, as recon emits
			"http://host.docker.internal:8080/wavsep/b.jsp",
		},
		FindingsRaw: []types.Finding{
			{Tool: "nuclei", CWE: []string{"CWE-89"}, Endpoint: "http://x/wavsep/a.jsp?p=1"},
		},
	}
	rep := ScoreWavsep(cases, scan)

	if rep.Coverage.ReachedCases != 2 || rep.Coverage.TotalCases != 3 {
		t.Errorf("coverage = %d/%d, want 2/3", rep.Coverage.ReachedCases, rep.Coverage.TotalCases)
	}
	if !rep.Coverage.Partial() {
		t.Error("a run that skipped a case must report Partial()")
	}
	if got := rep.Overall.TP + rep.Overall.FP + rep.Overall.TN + rep.Overall.FN; got != 2 {
		t.Errorf("graded %d cases, want 2 — the unvisited case must be excluded, not scored", got)
	}
	if rep.Overall.FN != 1 {
		t.Errorf("FN = %d, want exactly 1 (the crawled-but-missed case). If this is 2, the "+
			"never-visited case is being counted as a miss again.", rep.Overall.FN)
	}
}

// An empty surface is missing data, not proof of zero coverage (§10). Grading nothing would report a
// meaningless 0%; the honest fallback is to grade everything and say coverage is unknown.
func TestScoreWavsep_NoSurfaceGradesEverything(t *testing.T) {
	cases := []WavsepCase{
		{URL: "/wavsep/a.jsp", Category: "sqli", Vulnerable: true},
		{URL: "/wavsep/b.jsp", Category: "sqli", Vulnerable: true},
	}
	rep := ScoreWavsep(cases, &types.Scan{})
	if rep.Coverage.SurfaceKnown {
		t.Error("no discovered surface must read SurfaceKnown=false")
	}
	if got := rep.Overall.TP + rep.Overall.FP + rep.Overall.TN + rep.Overall.FN; got != 2 {
		t.Errorf("graded %d cases, want both — absent surface data must not silently drop cases", got)
	}
	if rep.Coverage.Partial() {
		t.Error("unknown coverage must not claim Partial(); it is unknown, not measured")
	}
}

// A truncated scan's misses are unfinished work, not detection failures. The engine records this
// (types.Scan.Partial); no bench scorer read it, so a timed-out run's recall was published as though
// every tool had run to completion — which is exactly how a throughput problem gets misread as a
// recall problem.
func TestScoreWavsep_ReportsTruncatedScan(t *testing.T) {
	cases := []WavsepCase{{URL: "/wavsep/a.jsp", Category: "sqli", Vulnerable: true}}
	scan := &types.Scan{
		DiscoveredSurface: []string{"http://h/wavsep/a.jsp"},
		Partial:           true,
		StopReason:        "deadline exceeded",
	}
	rep := ScoreWavsep(cases, scan)
	if !rep.Coverage.Truncated {
		t.Error("a partial scan must be reported as truncated, else its misses read as real misses")
	}
	out := RenderWavsep(rep)
	if !strings.Contains(out, "TRUNCATED") || !strings.Contains(out, "deadline exceeded") {
		t.Errorf("scorecard must disclose truncation and its reason, got:\n%s", out)
	}
}

// A partial run is crawl-ordered, not sampled. Measured live: at cap 15 every XSS case reached was
// DOM-XSS — 4 of the corpus's 98 XSS cases, and precisely the subset that needs JS execution to
// detect. Reading "xss 0%" off that slice would generalise the hardest 4% to the whole class, so the
// scorecard has to say the slice is not representative, not merely that it is small.
func TestRenderWavsep_PartialWarnsSampleIsNotRandom(t *testing.T) {
	cases := []WavsepCase{
		{URL: "/wavsep/a.jsp", Category: "xss", Vulnerable: true},
		{URL: "/wavsep/z.jsp", Category: "xss", Vulnerable: true},
	}
	rep := ScoreWavsep(cases, &types.Scan{DiscoveredSurface: []string{"http://h/wavsep/a.jsp"}})
	out := RenderWavsep(rep)
	if !strings.Contains(out, "NOT A RANDOM SAMPLE") {
		t.Errorf("a partial scorecard must warn the slice is crawl-ordered, not sampled; got:\n%s", out)
	}
}
