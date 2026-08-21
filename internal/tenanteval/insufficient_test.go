package tenanteval

import (
	"testing"

	"github.com/ClatTribe/tsengine/internal/detect"
	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

func liveFinding() types.Finding {
	return types.Finding{ID: "f-live", RuleID: "nuclei::sqli", Endpoint: "https://x/search",
		Severity: types.SeverityHigh}
}

// The free Policy-4 corpus: an applied fix whose rescan said "gone" while the exploit
// still ran becomes a Keep case, because the pipeline was one step from telling a
// customer they were safe.
func TestBuildSuite_EvidenceInsufficiencyBecomesACase(t *testing.T) {
	f := liveFinding()
	act := platform.Action{ID: "a1", Status: platform.ActApplied, FindingID: f.ID,
		Verification: &platform.FixVerification{
			Status: "still_exploitable", RescanSaidFixed: true,
			Disagreement: platform.DisagreeRescanMissedLiveExploit,
			StillPresent: []string{detect.Key(f)},
		}}
	cases := BuildSuite([]types.Finding{f}, nil, nil, []platform.Action{act})

	var got *Case
	for i := range cases {
		if cases[i].Source == SourceEvidenceInsufficient {
			got = &cases[i]
		}
	}
	if got == nil {
		t.Fatal("a proven-insufficient verification is the strongest free case there is and must be collected")
	}
	if got.Expect != Keep {
		t.Fatalf("the finding was real — the proof was not; want Keep, got %v", got.Expect)
	}
}

// Only the DANGEROUS conflict qualifies. The scanner-sees-variant case indicts the
// re-test playbook, not the filter, and folding it in would teach the wrong lesson.
func TestBuildSuite_ScannerSeesVariantIsNotAnEvidenceInsufficiencyCase(t *testing.T) {
	f := liveFinding()
	act := platform.Action{ID: "a1", Status: platform.ActApplied, FindingID: f.ID,
		Verification: &platform.FixVerification{
			Status: "closed_with_proof", Disagreement: platform.DisagreeScannerSeesVariant,
			StillPresent: []string{detect.Key(f)},
		}}
	for _, c := range BuildSuite([]types.Finding{f}, nil, nil, []platform.Action{act}) {
		if c.Source == SourceEvidenceInsufficient {
			t.Fatal("this conflict indicts the playbook, not the filter — different lesson, different source")
		}
	}
}

// The key must come from detect.Key, the same function that produced it. A hand-rolled
// key matched nothing for every tenant once already, and its test passed because the
// fixture copied the bug.
func TestBuildSuite_KeyIsComputedByTheSameFunctionThatAssignedIt(t *testing.T) {
	f := liveFinding()
	act := platform.Action{ID: "a1", Status: platform.ActApplied, FindingID: f.ID,
		Verification: &platform.FixVerification{
			Disagreement: platform.DisagreeRescanMissedLiveExploit,
			// Deliberately the WRONG format — what a hand-rolled key would produce.
			StillPresent: []string{f.RuleID + "|" + f.Endpoint + "|wrong"},
		}}
	for _, c := range BuildSuite([]types.Finding{f}, nil, nil, []platform.Action{act}) {
		if c.Source == SourceEvidenceInsufficient {
			t.Fatal("a key in the wrong format must match nothing rather than match by luck")
		}
	}
}

func TestBuildSuite_NoDisagreementYieldsNoInsufficiencyCases(t *testing.T) {
	f := liveFinding()
	act := platform.Action{ID: "a1", Status: platform.ActApplied, FindingID: f.ID,
		Verification: &platform.FixVerification{Status: platform.FixStatusFixed}}
	for _, c := range BuildSuite([]types.Finding{f}, nil, nil, []platform.Action{act}) {
		if c.Source == SourceEvidenceInsufficient {
			t.Fatal("a clean verification is not an example of insufficient evidence")
		}
	}
}
