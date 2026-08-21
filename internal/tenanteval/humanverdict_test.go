package tenanteval

import (
	"testing"

	"github.com/ClatTribe/tsengine/internal/crossdetect"
	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

func hv(id, endpoint string) types.Finding {
	return types.Finding{ID: id, RuleID: "semgrep::sqli", Endpoint: endpoint, Severity: types.SeverityHigh}
}

func caseFor(cases []Case, id string) *Case {
	for i := range cases {
		if cases[i].FindingID == id {
			return &cases[i]
		}
	}
	return nil
}

func TestBuildSuiteFrom_ExplicitVerdictBecomesACase(t *testing.T) {
	f := hv("f-1", "app.go:1")
	cases := BuildSuiteFrom(Inputs{
		Findings: []types.Finding{f},
		Feedback: []platform.Feedback{{IssueKey: crossdetect.DedupKey(f),
			Verdict: platform.FeedbackReal, Evidence: platform.EvidenceInsufficient, By: "cto@acme.com"}},
	})
	c := caseFor(cases, "f-1")
	if c == nil || c.Source != SourceHumanVerdict || c.Expect != Keep {
		t.Fatalf("a typed 'real' is a Keep case: %+v", c)
	}
	if !contains(c.Reason, "evidence did not show them why") {
		t.Fatalf("the evidence complaint should ride on the case for a reader: %q", c.Reason)
	}
}

// THE PRECEDENCE RULE. Someone who typed "false positive" has said something a
// suppression can only be read to imply. Where they disagree, the typed answer wins.
func TestBuildSuiteFrom_ExplicitVerdictOutranksAnInferredSuppression(t *testing.T) {
	f := hv("f-1", "app.go:1")
	key := crossdetect.DedupKey(f)
	cases := BuildSuiteFrom(Inputs{
		Findings: []types.Finding{f},
		// The click says "I accept this real risk"; the typed answer says it is wrong.
		Ignores:  []platform.IgnoreRule{{IssueKey: key, Reason: "accepted_risk"}},
		Feedback: []platform.Feedback{{IssueKey: key, Verdict: platform.FeedbackFalsePositive}},
	})
	c := caseFor(cases, "f-1")
	if c == nil || c.Source != SourceHumanVerdict {
		t.Fatalf("the explicit judgement must own the finding, got %+v", c)
	}
	if c.Expect != Suppress {
		t.Fatalf("the typed answer is the one they meant, got %v", c.Expect)
	}
	if len(cases) != 1 {
		t.Fatalf("one finding must yield one case, not one per source: %d", len(cases))
	}
}

// "unclear" says the write-up was unreadable, not that the finding is wrong. Filing it
// as either verdict would put words in someone's mouth.
func TestBuildSuiteFrom_UnclearProducesNoCase(t *testing.T) {
	f := hv("f-1", "app.go:1")
	cases := BuildSuiteFrom(Inputs{
		Findings: []types.Finding{f},
		Feedback: []platform.Feedback{{IssueKey: crossdetect.DedupKey(f), Verdict: platform.FeedbackUnclear}},
	})
	if len(cases) != 0 {
		t.Fatalf("an unreadable finding is a defect in the write-up, not a verdict: %+v", cases)
	}
}

// An evidence opinion alone is not a filter judgement — Score asks keep-or-suppress and
// "your proof was thin" does not answer that question.
func TestBuildSuiteFrom_EvidenceOpinionAloneIsNotAFilterCase(t *testing.T) {
	f := hv("f-1", "app.go:1")
	cases := BuildSuiteFrom(Inputs{
		Findings: []types.Finding{f},
		Feedback: []platform.Feedback{{IssueKey: crossdetect.DedupKey(f),
			Verdict: platform.FeedbackUnclear, Evidence: platform.EvidenceInsufficient}},
	})
	if len(cases) != 0 {
		t.Fatal("an opinion about our proof does not map onto keep-or-suppress")
	}
}

// The old positional entry point must keep behaving exactly as before.
func TestBuildSuite_LegacyEntryPointIsUnchanged(t *testing.T) {
	f := hv("f-1", "app.go:1")
	ig := platform.IgnoreRule{IssueKey: crossdetect.DedupKey(f), Reason: "false_positive"}
	cases := BuildSuite([]types.Finding{f}, nil, []platform.IgnoreRule{ig}, nil)
	c := caseFor(cases, "f-1")
	if c == nil || c.Source != SourceIgnored || c.Expect != Suppress {
		t.Fatalf("the wrapper must not change existing behaviour: %+v", c)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
