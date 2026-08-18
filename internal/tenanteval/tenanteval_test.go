package tenanteval

import (
	"testing"

	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// THE property that keeps this metric honest. A suite with no cases must have NO score — reporting
// 100% agreement would make the number rise as a customer does less, which is the shape of metric
// this codebase keeps refusing to emit.
func TestScore_EmptySuiteHasNoScoreAndSaysWhy(t *testing.T) {
	res := Score(nil)
	if _, ok := res.Agreement(); ok {
		t.Fatal("an empty suite reported an agreement score — a vacuous 100% that rewards inaction")
	}
	if res.Note == "" {
		t.Error("an empty suite must explain that there is nothing to score")
	}
	if res.Cases != 0 || res.Passed != 0 {
		t.Errorf("unexpected counts on an empty suite: %+v", res)
	}
}

// The suite is built from the customer's OWN decisions, and each kind carries its expected verdict.
func TestBuildSuite_DerivesCasesFromTheTenantsOwnJudgements(t *testing.T) {
	reinstated := types.Finding{
		ID: "f-rein", RuleID: "nuclei::tech-detect", Endpoint: "https://acme.test/",
		DiscoveryMethod: &types.DiscoveryMethod{Primary: "human_reinstated"},
	}
	fixedF := types.Finding{ID: "f-fixed", RuleID: "grype::CVE-2021-44228", Endpoint: "pkg:x"}
	noisy := types.Finding{ID: "f-noise", RuleID: "nuclei::banner", Endpoint: "https://acme.test/b"}

	cases := BuildSuite(
		[]types.Finding{reinstated, fixedF},
		[]types.Finding{noisy}, // dismissed by the chain
		[]platform.IgnoreRule{{IssueKey: "nuclei::banner|https://acme.test/b", Reason: "false_positive", By: "alex"}},
		[]platform.Action{{FindingID: "f-fixed", Verification: &platform.FixVerification{Status: "fixed"}}},
	)
	if len(cases) != 3 {
		t.Fatalf("want 3 cases (reinstated, ignored, confirmed fix), got %d: %+v", len(cases), cases)
	}
	want := map[string]struct {
		src Source
		exp Verdict
	}{
		"f-rein":  {SourceReinstated, Keep},
		"f-noise": {SourceIgnored, Suppress},
		"f-fixed": {SourceConfirmedFix, Keep},
	}
	for _, c := range cases {
		w, ok := want[c.FindingID]
		if !ok {
			t.Errorf("unexpected case %s", c.FindingID)
			continue
		}
		if c.Source != w.src || c.Expect != w.exp {
			t.Errorf("%s: got source=%s expect=%s, want source=%s expect=%s", c.FindingID, c.Source, c.Expect, w.src, w.exp)
		}
	}
}

// A reinstated finding is a human saying "this is real". If the current configuration would drop it
// AGAIN, that is a failure the tenant must see — it is the pipeline overruling their expert twice.
func TestScore_CatchesTheConfigurationDisagreeingWithAnExpert(t *testing.T) {
	// nuclei::tech-detect is a shape the FP filter dismisses, and a human reinstated it.
	c := Case{
		FindingID: "f-rein", RuleID: "nuclei::tech-detect", Source: SourceReinstated, Expect: Keep,
		finding: types.Finding{ID: "f-rein", RuleID: "nuclei::tech-detect", Tool: "nuclei",
			Severity: types.SeverityInfo, Endpoint: "https://acme.test/", Title: "Technology detected"},
	}
	res := Score([]Case{c})
	if res.Cases != 1 {
		t.Fatalf("want 1 case, got %d", res.Cases)
	}
	// Whichever way the current filter goes, the result must be self-consistent and attributed.
	if res.Passed+len(res.Failures) != res.Cases {
		t.Fatalf("passed+failures must equal cases, got %d+%d != %d", res.Passed, len(res.Failures), res.Cases)
	}
	if len(res.Failures) > 0 {
		f := res.Failures[0]
		if f.Source != SourceReinstated || f.Got == f.Expect {
			t.Errorf("a failure must record the disagreement and its source, got %+v", f)
		}
		if res.BySource[SourceReinstated] != 1 {
			t.Errorf("failures must be counted by source so the worst kind is visible, got %+v", res.BySource)
		}
	}
	if agree, ok := res.Agreement(); !ok || agree < 0 || agree > 1 {
		t.Errorf("agreement should be a real ratio, got %v ok=%v", agree, ok)
	}
}
