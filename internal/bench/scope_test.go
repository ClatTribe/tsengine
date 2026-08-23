package bench

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/ClatTribe/tsengine/pkg/types"
)

// A fixture's documented defect list is the HONEST DENOMINATOR behind its recall
// figure, and it spent its life being written and never read: the Fixture struct had
// no field for it, so json.Unmarshal dropped it silently and no report mentioned it.
// These tests pin the arithmetic and, more importantly, the direction it rounds.

func TestScopeCoverageIsAbsentWhenNothingIsDocumented(t *testing.T) {
	f := &Fixture{Name: "x", MustFind: []string{"a"}}
	if got := scopeCoverage(f); got != nil {
		t.Fatalf("a fixture documenting nothing must yield NO scope, got %+v.\n"+
			"An empty ScopeCoverage renders as 'documented: 0', which reads as a target with no "+
			"known defects rather than one whose defects were never enumerated.", got)
	}
}

func TestScopeCoverageCountsDetectableFromTheProseNotAFlag(t *testing.T) {
	f := &Fixture{
		MustFind: []string{"sqli"},
		DocumentedVulnerabilities: []DocumentedVuln{
			{Class: "SQL injection", CoveredBy: "nuclei + sqlmap"},
			{Class: "Excessive data exposure", CoveredBy: "NOT COVERED — no L1 detector"},
			{Class: "RegexDOS", CoveredBy: "not covered — needs load generation"}, // lowercase
		},
	}
	sc := scopeCoverage(f)
	if sc.Documented != 3 || sc.Detectable != 1 || sc.Measured != 1 {
		t.Fatalf("documented/detectable/measured = %d/%d/%d, want 3/1/1", sc.Documented, sc.Detectable, sc.Measured)
	}
	if len(sc.UncoveredClasses) != 2 {
		t.Fatalf("uncovered classes = %v, want both NOT-COVERED entries named", sc.UncoveredClasses)
	}
	// Lowercase must count too: the fixture is hand-written prose, and a case-sensitive
	// check would silently credit an uncovered class as covered.
	for _, c := range sc.UncoveredClasses {
		if c == "SQL injection" {
			t.Fatal("a covered class was reported uncovered")
		}
	}
}

// THE LOAD-BEARING RULE. An OWASP item with one covered class and one uncovered class
// is a GAP, not a win. Crediting it is the direction that overclaims, and it is the
// direction a careless implementation takes, because the covered class is seen first.
func TestPartialOWASPItemCountsAsUncovered(t *testing.T) {
	f := &Fixture{
		DocumentedVulnerabilities: []DocumentedVuln{
			{Class: "JWT bypass", CoveredBy: "nuclei jwt tags", OWASPAPI: "API2"},
			{Class: "User enumeration", CoveredBy: "NOT COVERED", OWASPAPI: "API2"},
			{Class: "BOLA", CoveredBy: "apiauthz", OWASPAPI: "API1"},
		},
	}
	sc := scopeCoverage(f)
	for _, id := range sc.OWASPCovered {
		if id == "API2" {
			t.Fatalf("API2 has an uncovered class and must NOT be reported covered; covered=%v", sc.OWASPCovered)
		}
	}
	if len(sc.OWASPCovered) != 1 || sc.OWASPCovered[0] != "API1" {
		t.Fatalf("covered = %v, want [API1] only", sc.OWASPCovered)
	}
	if len(sc.OWASPUncovered) != 1 || sc.OWASPUncovered[0] != "API2" {
		t.Fatalf("uncovered = %v, want [API2]", sc.OWASPUncovered)
	}
}

// A perfect recall figure must arrive WITH the denominator that qualifies it. This is
// the whole point: 1.000 over a one-item MustFind on a nine-defect target is not
// "we find everything".
func TestPerfectRecallCarriesItsDenominator(t *testing.T) {
	f := &Fixture{
		Name: "api-vampi", Metric: MetricMustFindRecall, PassRecall: 1.0,
		MustFind: []string{"sqli"},
		DocumentedVulnerabilities: []DocumentedVuln{
			{Class: "SQL injection", CoveredBy: "nuclei + sqlmap"},
			{Class: "Excessive data exposure", CoveredBy: "NOT COVERED"},
		},
	}
	scan := &types.Scan{FindingsRaw: []types.Finding{{RuleID: "sqlmap::sqli", Severity: types.SeverityHigh}}}
	s := ScoreScan(f, scan)
	if s.DetectionRecall != 1.0 {
		t.Fatalf("recall = %v, want 1.0", s.DetectionRecall)
	}
	if s.Scope == nil {
		t.Fatal("a perfect recall was reported with NO scope — the figure reads as total coverage")
	}
	if s.Scope.Documented != 2 || s.Scope.Measured != 1 {
		t.Fatalf("scope = %+v, want documented 2 / measured 1", s.Scope)
	}
}

// The real fixture must carry the mapping, or the per-item claim has no source.
func TestVAmPIFixtureMapsEveryClassItCanToTheTop10(t *testing.T) {
	path := filepath.Join("..", "..", "fixtures", "api", "vampi", "fixture.json")
	b, err := os.ReadFile(path)
	if err != nil {
		// Fail rather than skip: a guard that excuses itself when it cannot find its
		// subject reports green for the rest of its life (ADR 0022).
		t.Fatalf("cannot read %s: %v", path, err)
	}
	var f Fixture
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(f.DocumentedVulnerabilities) == 0 {
		t.Fatal("the VAmPI fixture documents no vulnerabilities — the denominator is gone")
	}
	sc := scopeCoverage(&f)
	if sc == nil || len(sc.OWASPUncovered) == 0 {
		t.Fatalf("expected VAmPI to expose uncovered OWASP items; scope=%+v", sc)
	}
	// SQL injection is deliberately unmapped — Injection was API8:2019 and was folded
	// away in 2023. Pinned so nobody "fixes" it by inventing an item for it.
	for _, d := range f.DocumentedVulnerabilities {
		if d.Class == "SQL injection" && d.OWASPAPI != "" {
			t.Errorf("SQL injection is mapped to %q; it is not a 2023 Top 10 item and mapping it "+
				"invents coverage of an item VAmPI does not exercise", d.OWASPAPI)
		}
	}
}
