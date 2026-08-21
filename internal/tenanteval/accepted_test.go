package tenanteval

import (
	"testing"

	"github.com/ClatTribe/tsengine/internal/crossdetect"
	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

func fx(id string) types.Finding {
	return types.Finding{ID: id, RuleID: "semgrep::sqli", Endpoint: "app.go:14", Severity: types.SeverityHigh}
}

func sourceOf(cases []Case, id string) Source {
	for _, c := range cases {
		if c.FindingID == id {
			return c.Source
		}
	}
	return ""
}

// The one reason a customer gives that AGREES with us was producing no signal at all.
func TestBuildSuite_AcceptedRiskIsAKeepCaseNotSilence(t *testing.T) {
	f := fx("f-1")
	ig := platform.IgnoreRule{IssueKey: crossdetect.DedupKey(f), Reason: "accepted_risk", By: "cto@acme.com"}
	cases := BuildSuite([]types.Finding{f}, nil, []platform.IgnoreRule{ig}, nil)

	if got := sourceOf(cases, "f-1"); got != SourceAcceptedRisk {
		t.Fatalf("accepting a risk presupposes the risk is real — want a Keep case, got source %q", got)
	}
	for _, c := range cases {
		if c.FindingID == "f-1" && c.Expect != Keep {
			t.Fatalf("want Keep, got %v", c.Expect)
		}
	}
}

// The two verdicts come from the same control and must not blur.
func TestBuildSuite_FalsePositiveAndAcceptedRiskAreOppositeVerdicts(t *testing.T) {
	a, b := fx("f-fp"), fx("f-ar")
	b.Endpoint = "other.go:9" // distinct key
	cases := BuildSuite([]types.Finding{a, b}, nil, []platform.IgnoreRule{
		{IssueKey: crossdetect.DedupKey(a), Reason: "false_positive"},
		{IssueKey: crossdetect.DedupKey(b), Reason: "accepted_risk"},
	}, nil)

	var fp, ar *Case
	for i := range cases {
		switch cases[i].FindingID {
		case "f-fp":
			fp = &cases[i]
		case "f-ar":
			ar = &cases[i]
		}
	}
	if fp == nil || ar == nil {
		t.Fatalf("both suppressions should produce cases, got %d", len(cases))
	}
	if fp.Expect != Suppress || ar.Expect != Keep {
		t.Fatalf("opposite verdicts: fp=%v ar=%v", fp.Expect, ar.Expect)
	}
}

// wont_fix is ambiguous and must stay out until it means one thing.
func TestBuildSuite_WontFixIsNotRecordedEitherWay(t *testing.T) {
	f := fx("f-wf")
	cases := BuildSuite([]types.Finding{f}, nil,
		[]platform.IgnoreRule{{IssueKey: crossdetect.DedupKey(f), Reason: "wont_fix"}}, nil)
	if len(cases) != 0 {
		t.Fatalf("an ambiguous reason must not be filed as either verdict, got %+v", cases)
	}
}
