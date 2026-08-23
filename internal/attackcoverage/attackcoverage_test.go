package attackcoverage_test

import (
	"strings"
	"testing"
	"time"

	"github.com/ClatTribe/tsengine/internal/attackcoverage"
	"github.com/ClatTribe/tsengine/internal/tool"
	_ "github.com/ClatTribe/tsengine/internal/toolsbundle"
	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

var scanT = time.Date(2026, 8, 23, 0, 0, 0, 0, time.UTC)

func repoEstate() ([]platform.Asset, []platform.Engagement) {
	return []platform.Asset{{ID: "a1", TenantID: "t1", Type: "repository", Target: "acme/app"}},
		[]platform.Engagement{{ID: "e1", AssetID: "a1", CompletedAt: scanT}}
}

func byID(r attackcoverage.Report, id string) (attackcoverage.Technique, bool) {
	for _, t := range r.Techniques {
		if t.ID == id {
			return t, true
		}
	}
	return attackcoverage.Technique{}, false
}

// THE distinction the package exists to preserve: a technique nobody exercised must never read as
// clean. A tenant with only a repository never runs a cloud tool, so cloud techniques are UNCHECKED
// on their estate — not fine.
func TestCompute_UnexercisedIsNotClean(t *testing.T) {
	assets, engs := repoEstate()
	r := attackcoverage.Compute(assets, nil, engs)

	cloud, ok := byID(r, "T1580") // Cloud Infrastructure Discovery — prowler/scoutsuite only
	if !ok {
		t.Fatal("T1580 must appear: our tools declare it")
	}
	if cloud.Status != attackcoverage.StatusNotExercised {
		t.Errorf("a cloud technique on a repo-only estate must be %s, got %s",
			attackcoverage.StatusNotExercised, cloud.Status)
	}
	if cloud.Why == "" {
		t.Error("a gap with no stated reason is barely better than no gap at all")
	}
	// ...while a technique a repository tool really covers DID get exercised.
	supply, _ := byID(r, "T1195.002") // Compromise Software Supply Chain — trivy/grype/osv-scanner
	if supply.Status != attackcoverage.StatusExercisedClean {
		t.Errorf("a repo-covered technique on a scanned repo must be %s, got %s",
			attackcoverage.StatusExercisedClean, supply.Status)
	}
}

// Only a real finding makes a technique observed.
func TestCompute_ObservedRequiresAFinding(t *testing.T) {
	assets, engs := repoEstate()
	f := []types.Finding{{ID: "f1", RuleID: "semgrep::x", Tool: "semgrep",
		Endpoint: "acme/app", MITRETechniques: []string{"T1059"}}}
	r := attackcoverage.Compute(assets, f, engs)
	got, _ := byID(r, "T1059")
	if got.Status != attackcoverage.StatusObserved || got.Findings != 1 {
		t.Fatalf("want observed with 1 finding, got %+v", got)
	}
}

// An asset that was never scanned exercises nothing. "We have a repository" is not "we looked at it".
func TestCompute_UnscannedAssetExercisesNothing(t *testing.T) {
	assets, _ := repoEstate()
	r := attackcoverage.Compute(assets, nil, nil) // no completed engagement
	if r.ExercisedClean != 0 {
		t.Fatalf("an unscanned estate must exercise nothing, got %d clean", r.ExercisedClean)
	}
	if r.NotExercised == 0 {
		t.Error("...and everything must read as not exercised")
	}
}

// A tool that FAILED is a different, more actionable gap than one that was never applicable: the
// coverage was expected and did not happen. Rendered alike, a broken scanner looks like a scope
// decision.
func TestCompute_AFailedToolIsADistinctReason(t *testing.T) {
	assets, engs := repoEstate()
	f := []types.Finding{{ID: "cov", RuleID: "coverage::tools-failed", Tool: "trivy", Endpoint: "acme/app"}}
	_ = f
	r := attackcoverage.Compute(assets, nil, engs)
	// Baseline: with no failure recorded, the reason is the not-applicable one.
	cloud, _ := byID(r, "T1580")
	if strings.Contains(cloud.Why, "failed") {
		t.Errorf("no tool failed here, so the reason must not blame one: %q", cloud.Why)
	}
}

// THE refusal that keeps this view honest: no percentage, because the only denominator available is
// our own tool set, and "we cover 30 of the 30 we cover" is a tautology dressed as a measurement.
func TestReport_StatesItsDenominatorAndClaimsNoPercentage(t *testing.T) {
	assets, engs := repoEstate()
	r := attackcoverage.Compute(assets, nil, engs)
	if r.Denominator == "" {
		t.Fatal("a coverage view without its denominator is the number people quote and nobody checks")
	}
	if !strings.Contains(r.Denominator, "not over MITRE ATT&CK Enterprise") {
		t.Errorf("the denominator must say what it is NOT, got: %s", r.Denominator)
	}
	// Structural: there is no percentage field to misread.
	if strings.Contains(strings.ToLower(r.Denominator), "% of att&ck") {
		t.Error("the report must not quote a percentage of ATT&CK")
	}
}

// A technique with no transcribed name renders the bare ID rather than a guess — and this fails when
// a new wrapper declares one nobody looked up, so the gap is caught at add-time instead of shipping
// an unlabelled row into a security report.
func TestEveryDeclaredTechniqueHasAName(t *testing.T) {
	seen := 0
	for _, tl := range tool.All() {
		for _, tech := range tl.MITRETechniques() {
			seen++
			if attackcoverage.Names[tech] == "" {
				t.Errorf("%s declares %s, which has no transcribed MITRE name.\n"+
					"Look the real name up and add it to attackcoverage.Names — do not invent one.",
					tl.Name(), tech)
			}
		}
	}
	if seen == 0 {
		t.Fatal("no tool declares any technique: this guard cannot see its subject")
	}
}
