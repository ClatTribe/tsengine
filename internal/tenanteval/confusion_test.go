package tenanteval

import (
	"context"
	"testing"

	"github.com/ClatTribe/tsengine/pkg/types"
)

// confusion_test.go covers (c): the FP-rejection (specificity) breakdown — the trust number a buyer
// asks for, isolated from recall, with honest denominators.

func TestConfusion_SpecificityAndRecallOverAKnownMatrix(t *testing.T) {
	var c Confusion
	// 3 findings the human called false positives: 2 correctly dropped, 1 wrongly kept.
	c.observe(Suppress, Suppress)
	c.observe(Suppress, Suppress)
	c.observe(Suppress, Keep)
	// 2 findings the human said are real: 1 kept, 1 wrongly dropped.
	c.observe(Keep, Keep)
	c.observe(Keep, Suppress)

	if spec, ok := c.Specificity(); !ok || spec < 0.66 || spec > 0.67 {
		t.Errorf("FP-rejection over 2/3 correct rejects should be ~0.667, got %v ok=%v", spec, ok)
	}
	if rec, ok := c.Recall(); !ok || rec != 0.5 {
		t.Errorf("recall over 1/2 kept should be 0.5, got %v ok=%v", rec, ok)
	}
	if c.RejectedRight != 2 || c.RejectedWrong != 1 || c.KeptRight != 1 || c.KeptWrong != 1 {
		t.Errorf("matrix cells wrong: %+v", c)
	}
}

// The vacuous-pass guard (§14.2 rule 6): a specificity over zero false positives, or a recall over
// zero real findings, is undefined — never a perfect score for a corpus with nothing to get wrong.
func TestConfusion_HonestDenominators(t *testing.T) {
	var empty Confusion
	if _, ok := empty.Specificity(); ok {
		t.Error("specificity over zero suppress cases must be undefined, not a number")
	}
	if _, ok := empty.Recall(); ok {
		t.Error("recall over zero keep cases must be undefined, not a number")
	}

	var onlyKeeps Confusion
	onlyKeeps.observe(Keep, Keep)
	if _, ok := onlyKeeps.Specificity(); ok {
		t.Error("no false positives to reject ⇒ specificity is undefined, never a vacuous 100%")
	}
	if _, ok := onlyKeeps.Recall(); !ok {
		t.Error("with keep cases, recall must be defined")
	}
}

// Score's confusion is consistent with Passed no matter which way the live L1.5 chain goes: the two
// "right" cells sum to Passed and all four cells sum to Cases. This holds without controlling the
// chain's verdict, so it can never rot into a number that disagrees with the headline.
func TestScore_ConfusionIsConsistentWithPassed(t *testing.T) {
	cases := []Case{
		{FindingID: "k", RuleID: "nuclei::sqli", Source: SourceReinstated, Expect: Keep,
			finding: types.Finding{ID: "k", RuleID: "nuclei::sqli", Tool: "nuclei",
				Severity: types.SeverityHigh, Endpoint: "https://acme.test/a", Title: "SQLi"}},
		{FindingID: "s", RuleID: "nuclei::tech-detect", Source: SourceIgnored, Expect: Suppress,
			finding: types.Finding{ID: "s", RuleID: "nuclei::tech-detect", Tool: "nuclei",
				Severity: types.SeverityInfo, Endpoint: "https://acme.test/b", Title: "Tech detected"}},
	}
	res := Score(cases)
	c := res.Confusion
	if c.KeptRight+c.RejectedRight != res.Passed {
		t.Errorf("confusion 'right' cells (%d+%d) must equal Passed (%d)", c.KeptRight, c.RejectedRight, res.Passed)
	}
	if c.KeptRight+c.KeptWrong+c.RejectedRight+c.RejectedWrong != res.Cases {
		t.Errorf("confusion cells must sum to Cases (%d), got %+v", res.Cases, c)
	}
}

type scriptedJudge struct {
	v   map[string]Verdict
	err map[string]error
}

func (j scriptedJudge) Judge(_ context.Context, f types.Finding) (Verdict, error) {
	if e := j.err[f.ID]; e != nil {
		return "", e
	}
	return j.v[f.ID], nil
}

// The model arm's confusion is built over ANSWERED cases only. An unanswered case (an error) has no
// verdict to place — counting silence as a reject or a keep would be a false number — so it is
// excluded here and counted by Unanswered instead.
func TestScoreModel_ConfusionExcludesUnanswered(t *testing.T) {
	cases := []Case{
		{FindingID: "a", Expect: Suppress, finding: types.Finding{ID: "a"}},
		{FindingID: "b", Expect: Suppress, finding: types.Finding{ID: "b"}},
		{FindingID: "c", Expect: Keep, finding: types.Finding{ID: "c"}},
	}
	judge := scriptedJudge{
		v:   map[string]Verdict{"a": Suppress, "c": Keep}, // a: correct reject, c: correct keep
		err: map[string]error{"b": context.DeadlineExceeded},
	}
	res, err := ScoreModel(context.Background(), cases, judge)
	if err != nil {
		t.Fatalf("ScoreModel: %v", err)
	}
	if res.Unanswered != 1 {
		t.Fatalf("want 1 unanswered, got %d", res.Unanswered)
	}
	c := res.Confusion
	total := c.KeptRight + c.KeptWrong + c.RejectedRight + c.RejectedWrong
	if total != res.Cases-res.Unanswered {
		t.Errorf("confusion must cover only answered cases (%d), got %d (%+v)", res.Cases-res.Unanswered, total, c)
	}
	// Only 'a' was an answered suppress case, correctly rejected → specificity 1.0 over 1, and the
	// unanswered 'b' must NOT drag it down (it is not evidence the model kept a fake).
	if spec, ok := c.Specificity(); !ok || spec != 1.0 {
		t.Errorf("specificity over the one answered reject should be 1.0, got %v ok=%v", spec, ok)
	}
}
