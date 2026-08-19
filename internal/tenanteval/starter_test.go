package tenanteval

import (
	"context"
	"strings"
	"testing"
)

// A check a constant answerer passes measures nothing. This is the FP-control discipline the
// benchmarks already apply, asserted here because an unbalanced starter set is the easy mistake:
// the obvious cases to write are all "this is real, keep it".
func TestStarter_ConstantAnswererCannotPass(t *testing.T) {
	keep, suppress := StarterBalance()
	if keep == 0 || suppress == 0 {
		t.Fatalf("starter check is one-sided (%d keep, %d suppress) — answering one word always passes", keep, suppress)
	}
	for _, always := range []Verdict{Keep, Suppress} {
		res, err := ScoreModel(context.Background(), StarterCases(), &fakeJudge{verdict: always})
		if err != nil {
			t.Fatal(err)
		}
		if res.Passed == res.Cases {
			t.Errorf("a model that always answers %q scored %d/%d", always, res.Passed, res.Cases)
		}
	}
}

// Every answer must be checkable by the customer rather than taken on our word. A case we cannot
// cite has no business being in the set.
func TestStarter_EveryCaseCitesItsAuthority(t *testing.T) {
	for _, c := range StarterCases() {
		if strings.TrimSpace(c.Reason) == "" {
			t.Errorf("%s states no reason", c.FindingID)
			continue
		}
		// The rationale must point at something outside us — the vendor or the authority that
		// settles it — not merely assert the answer.
		low := strings.ToLower(c.Reason)
		cites := strings.Contains(low, "cisa") || strings.Contains(low, "stripe") ||
			strings.Contains(low, "aws")
		if !cites {
			t.Errorf("%s cites no external authority: %q", c.FindingID, c.Reason)
		}
	}
}

// The starter cases are OURS. Folding them into the tenant's suite would destroy the one thing that
// number is worth — that every case in it is the customer's own judgement.
func TestStarter_IsNotPartOfTheTenantsOwnSuite(t *testing.T) {
	cases := BuildSuite(nil, nil, nil, nil)
	if len(cases) != 0 {
		t.Fatalf("a tenant with no decisions got %d case(s) — the starter set leaked into their suite", len(cases))
	}
	for _, c := range StarterCases() {
		if c.Source != SourceStarter {
			t.Errorf("%s is not marked as a starter case (%q) — it could be read as the customer's", c.FindingID, c.Source)
		}
		if c.By != "" {
			t.Errorf("%s names %q as the human who judged it; nobody at this customer did", c.FindingID, c.By)
		}
	}
}

// The two suppress cases are the ones that matter: both are strings their own vendors publish as
// examples. A grader that reports them is producing the alert that teaches a team to ignore alerts.
func TestStarter_PublishedExamplesAreSuppressCases(t *testing.T) {
	want := map[string]bool{"starter-aws-doc-example": true, "starter-publishable-key": true}
	for _, c := range StarterCases() {
		if want[c.FindingID] && c.Expect != Suppress {
			t.Errorf("%s expects %q; a vendor-published example is not a live credential", c.FindingID, c.Expect)
		}
	}
}
