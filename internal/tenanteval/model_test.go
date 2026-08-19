package tenanteval

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/pkg/types"
)

type fakeJudge struct {
	verdict Verdict
	err     error
	seen    []string
}

func (f *fakeJudge) Judge(_ context.Context, fi types.Finding) (Verdict, error) {
	f.seen = append(f.seen, PromptFor(fi))
	return f.verdict, f.err
}

func caseSet(n int, expect Verdict) []Case {
	var cs []Case
	for i := 0; i < n; i++ {
		cs = append(cs, Case{
			FindingID: string(rune('a' + i)), RuleID: "r", Source: SourceIgnored, Expect: expect,
			finding: types.Finding{ID: string(rune('a' + i)), RuleID: "r", Severity: types.SeverityHigh},
		})
	}
	return cs
}

// "We could not ask the model" and "the model did badly" are different facts. Reporting the first
// as a zero would tell a customer their model is useless when it was never run.
func TestScoreModel_NoModelIsAnErrorNotAZero(t *testing.T) {
	_, err := ScoreModel(context.Background(), caseSet(6, Keep), nil)
	if !errors.Is(err, ErrNoModel) {
		t.Fatalf("want ErrNoModel, got %v", err)
	}
}

// A model that answers three of twenty correctly has not scored 100%.
func TestScoreModel_UnansweredCountsAgainstTheScore(t *testing.T) {
	res, err := ScoreModel(context.Background(), caseSet(6, Keep), &fakeJudge{err: errors.New("timeout")})
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if res.Passed != 0 {
		t.Errorf("a model that answered nothing passed %d case(s)", res.Passed)
	}
	if res.Unanswered != 6 {
		t.Errorf("unanswered = %d, want 6 — a broken model must be distinguishable from a wrong one", res.Unanswered)
	}
	if got, _ := res.Agreement(); got != 0 {
		t.Errorf("agreement %.2f over zero answers", got)
	}
}

// An ambiguous reply is not an answer. Guessing which word it "meant" manufactures agreement.
func TestParseVerdict_RefusesAmbiguity(t *testing.T) {
	for _, reply := range []string{"KEEP or SUPPRESS?", "suppress... actually keep", "maybe"} {
		if v, ok := ParseVerdict(reply); ok {
			t.Errorf("read %q as a definite %q", reply, v)
		}
	}
	if v, ok := ParseVerdict("  keep  "); !ok || v != Keep {
		t.Errorf("a clear answer must parse, got %q ok=%v", v, ok)
	}
}

// A grader that can see the answer key measures nothing.
func TestPromptFor_DoesNotLeakTheExpectedAnswer(t *testing.T) {
	j := &fakeJudge{verdict: Keep}
	cs := caseSet(3, Suppress)
	cs[0].Reason = "our team said this is noise in the vendor directory"
	cs[0].By = "alice@acme.com"
	if _, err := ScoreModel(context.Background(), cs, j); err != nil {
		t.Fatal(err)
	}
	for _, p := range j.seen {
		low := strings.ToLower(p)
		for _, leak := range []string{"suppress as noise", "ignored", "reinstated", "confirmed_fix", "alice@acme.com", "our team said"} {
			if strings.Contains(low, strings.ToLower(leak)) && leak != "suppress as noise" {
				t.Errorf("prompt leaks the answer key (%q):\n%s", leak, p)
			}
		}
	}
}

// The comparison must refuse to declare a winner it cannot support.
func TestCompare_RefusesWhatItCannotCompare(t *testing.T) {
	// Different case counts: not comparable at all.
	a := Compare(Result{Cases: 10, Passed: 8}, ModelResult{Cases: 7, Passed: 7})
	if a.Meaningful || !strings.Contains(a.Verdict, "cannot be compared") {
		t.Errorf("compared two arms over different case sets: %+v", a)
	}
	// Same cases but too few to mean anything.
	a = Compare(Result{Cases: 3, Passed: 1}, ModelResult{Cases: 3, Passed: 3})
	if a.Meaningful {
		t.Errorf("called a 3-case delta meaningful: %+v", a)
	}
	if a.Delta != 2 {
		t.Errorf("delta should still be reported even when not meaningful, got %d", a.Delta)
	}
	// A real comparison.
	a = Compare(Result{Cases: 10, Passed: 6}, ModelResult{Cases: 10, Passed: 9})
	if !a.Meaningful || a.Delta != 3 || !strings.Contains(a.Verdict, "3 more") {
		t.Errorf("want a meaningful +3, got %+v", a)
	}
	// A tie must not be dressed as a win for either side.
	a = Compare(Result{Cases: 10, Passed: 7}, ModelResult{Cases: 10, Passed: 7})
	if !strings.Contains(a.Verdict, "equally") {
		t.Errorf("tie reported as %q", a.Verdict)
	}
}

// An empty suite must not score 100% — the metric that rises as a customer does less.
func TestScoreModel_EmptySuiteScoresNothing(t *testing.T) {
	res, err := ScoreModel(context.Background(), nil, &fakeJudge{verdict: Keep})
	if err != nil {
		t.Fatal(err)
	}
	if _, meaningful := res.Agreement(); meaningful {
		t.Error("an empty suite reported a meaningful agreement")
	}
	if res.Note == "" {
		t.Error("an empty suite must say why it is empty")
	}
}

// "unanswered: 1" on its own is a dead end — a wrong key, a rate limit, and a chatty model look
// identical, and the customer cannot tell which one to fix. Found live: a real run came back
// unanswered with no way to see it was an HTTP 429.
func TestScoreModel_SaysWhyACaseWentUnanswered(t *testing.T) {
	res, err := ScoreModel(context.Background(), caseSet(2, Keep),
		&fakeJudge{err: errors.New("gemini: gemini-3.5-flash returned HTTP 429")})
	if err != nil {
		t.Fatal(err)
	}
	if res.UnansweredReason == "" {
		t.Fatal("a model that never answered reported no reason")
	}
	if !strings.Contains(res.UnansweredReason, "429") {
		t.Errorf("reason does not carry the actual failure: %q", res.UnansweredReason)
	}
}

// A model that replies with prose rather than a verdict is a different failure from a model that
// errored, and must not be reported as one.
func TestScoreModel_DistinguishesAnUnreadableReplyFromAnError(t *testing.T) {
	res, err := ScoreModel(context.Background(), caseSet(2, Keep), &fakeJudge{verdict: "perhaps"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(res.UnansweredReason, "not with KEEP or SUPPRESS") {
		t.Errorf("an unreadable reply was reported as %q", res.UnansweredReason)
	}
}
