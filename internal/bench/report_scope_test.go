package bench

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/pkg/types"
)

// The scope exists so a perfect recall over a one-token must_find cannot be read as total
// coverage. It was computed and rendered NOWHERE, which left the report saying exactly
// what the scope exists to prevent — the same computed-for-nobody defect this codebase
// keeps finding, introduced by the change meant to fix it. These pin the reader half.

func renderFor(t *testing.T, f *Fixture, scan *types.Scan) string {
	t.Helper()
	s := ScoreScan(f, scan)
	return Render(f, &RunResult{Scores: []Score{s}})
}

func TestReportPrintsTheDenominatorBesideTheRecall(t *testing.T) {
	f := &Fixture{
		Name: "api-vampi", Asset: "api", Metric: MetricMustFindRecall, PassRecall: 1.0,
		MustFind:    []string{"sqli"},
		Competitors: Competitors{Note: "no neutral API leaderboard exists"},
		DocumentedVulnerabilities: []DocumentedVuln{
			{Class: "SQL injection", CoveredBy: "nuclei + sqlmap"},
			{Class: "BOLA", CoveredBy: "apiauthz", OWASPAPI: "API1", Gated: true},
			{Class: "Rate limiting", CoveredBy: "NOT COVERED", OWASPAPI: "API4"},
		},
	}
	scan := &types.Scan{FindingsRaw: []types.Finding{{RuleID: "sqlmap::sqli", Severity: types.SeverityHigh}}}
	out := renderFor(t, f, scan)

	if !strings.Contains(out, "detection recall") {
		t.Fatalf("report lost its recall line:\n%s", out)
	}
	for _, want := range []string{
		"scope:",
		"2 of 3", // SQLi covered + BOLA gated are both DETECTABLE; only rate limiting is not
		"OWASP gated:",
		"API1",
		"OWASP uncovered:",
		"API4",
		"NOT DETECTED:",
		"Rate limiting",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("report is missing %q — the recall figure travels without the denominator that qualifies it.\n%s", want, out)
		}
	}
}

// A fixture with no documented list must print NO scope. An empty one would read as a
// target with no known defects rather than one whose defects were never enumerated.
func TestReportOmitsScopeWhenNothingIsDocumented(t *testing.T) {
	f := &Fixture{
		Name: "plain", Asset: "api", Metric: MetricMustFindRecall, PassRecall: 1.0,
		MustFind: []string{"x"}, Competitors: Competitors{Note: "n/a"},
	}
	out := renderFor(t, f, &types.Scan{})
	if strings.Contains(out, "scope:") {
		t.Errorf("scope printed for a fixture documenting nothing:\n%s", out)
	}
}

// The real fixture, rendered. This is the number a human actually reads, so it is worth
// asserting on the artifact rather than only on a constructed one.
func TestVAmPIReportShowsTheGatedPicture(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "fixtures", "api", "vampi", "fixture.json"))
	if err != nil {
		t.Fatalf("cannot read the VAmPI fixture: %v", err) // fail, never skip
	}
	var f Fixture
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatalf("parse: %v", err)
	}
	out := renderFor(t, &f, &types.Scan{FindingsRaw: []types.Finding{{RuleID: "sqlmap::sqli"}}})
	if !strings.Contains(out, "OWASP gated:") {
		t.Errorf("the VAmPI report does not disclose its gated items; a reader would take the recall at face value.\n%s", out)
	}
	if strings.Contains(out, "OWASP covered:") {
		t.Errorf("VAmPI reports an item as COVERED. Every item it exercises is gated or uncovered — "+
			"if that changed, this test should be updated deliberately rather than by surprise.\n%s", out)
	}
}
