package tenanteval

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/ClatTribe/tsengine/pkg/types"
)

// THE SECOND GRADER.
//
// Score answers "does today's FILTER agree with this tenant's experts?" — a deterministic question
// about a deterministic chain. It is not the question a customer with their own API key has. They
// can point both agents at any model, and nothing in the product tells them whether the model they
// chose is any good on THEIR estate. A public benchmark cannot tell them either: it measures a
// generic notion of good security work, not this customer's.
//
// So the same cases get a second grader. Identical questions, identical ground truth, one arm
// deterministic and one arm the tenant's configured model — which makes the interesting number not
// either score but the DIFFERENCE. A model that disagrees with the filter is not automatically
// wrong; the cases say which of them the customer's own people agreed with.
//
// The model is only ever GRADED here. It cannot suppress, keep, or alter a single real finding
// through this path — the pipeline's verdicts still come from the chain (§10: the model proposes,
// the framework disposes). An eval that let the thing being measured change the system it is
// measured on would be worthless twice over.

// ModelJudge answers one case. Implementations wrap whatever LLM the tenant configured.
type ModelJudge interface {
	// Judge returns the model's verdict for a finding. An error means the model did not answer;
	// it must never be reported as agreement.
	Judge(ctx context.Context, f types.Finding) (Verdict, error)
}

// ErrNoModel is returned when no model is configured for the tenant. It is deliberately an error
// rather than a zero score: "we could not ask" and "the model did badly" are different facts, and
// a customer reading a 0 would draw exactly the wrong conclusion about a model they never ran.
var ErrNoModel = errors.New("tenanteval: no model configured for this tenant")

// ModelResult is the model arm's score over the same suite.
type ModelResult struct {
	Model  string `json:"model,omitempty"`
	Cases  int    `json:"cases"`
	Passed int    `json:"passed"`
	// Unanswered counts cases the model failed to answer at all (an error, a timeout, an
	// unparseable reply). They are counted as NOT passed, because a model that answers three of
	// twenty and gets them right has not scored 100% — it has scored 15%. Reported separately so a
	// broken key is distinguishable from a model that is merely wrong.
	Unanswered int `json:"unanswered"`
	// UnansweredReason is WHY the first unanswered case went unanswered. Without it "unanswered: 1"
	// is a dead end: a wrong key, a rate limit, a model that replied with an essay, and a model that
	// is simply unavailable all look identical, and the customer cannot tell which of them to fix.
	// Bounded and never the raw provider payload.
	UnansweredReason string         `json:"unanswered_reason,omitempty"`
	Failures         []Failure      `json:"failures"`
	BySource         map[Source]int `json:"by_source"`
	Note             string         `json:"note,omitempty"`
}

// Agreement mirrors Result.Agreement: the ratio, and whether it means anything yet.
func (r ModelResult) Agreement() (float64, bool) {
	if r.Cases == 0 {
		return 0, false
	}
	return float64(r.Passed) / float64(r.Cases), r.Cases >= minMeaningfulCases
}

// minMeaningfulCases is the floor below which a percentage is noise wearing a decimal point — one
// case moves it by tens of points. Matches the threshold Score already applies to its own note.
const minMeaningfulCases = 5

// ScoreModel replays the SAME cases through the tenant's model.
func ScoreModel(ctx context.Context, cases []Case, judge ModelJudge) (ModelResult, error) {
	if judge == nil {
		return ModelResult{}, ErrNoModel
	}
	res := ModelResult{Cases: len(cases), BySource: map[Source]int{}, Failures: []Failure{}}
	if len(cases) == 0 {
		res.Note = noCasesNote
		return res, nil
	}
	for _, c := range cases {
		got, err := judge.Judge(ctx, c.finding)
		if err != nil || (got != Keep && got != Suppress) {
			// Not an answer. Counted against the score and surfaced, never silently skipped.
			res.Unanswered++
			if res.UnansweredReason == "" {
				res.UnansweredReason = reasonFor(err)
			}
			res.BySource[c.Source]++
			res.Failures = append(res.Failures, Failure{Case: c, Got: ""})
			continue
		}
		if got == c.Expect {
			res.Passed++
			continue
		}
		res.BySource[c.Source]++
		res.Failures = append(res.Failures, Failure{Case: c, Got: got})
	}
	if res.Cases < minMeaningfulCases {
		res.Note = smallSuiteNote
	}
	return res, nil
}

// Ablation is the comparison a customer actually wants: on the cases their own people graded, does
// the model agree with them more or less often than the deterministic filter does?
type Ablation struct {
	SubstratePassed int `json:"substrate_passed"`
	ModelPassed     int `json:"model_passed"`
	Cases           int `json:"cases"`
	// Delta is model minus substrate, in cases. Positive means the model agreed with this tenant's
	// experts more often than the filter did.
	Delta int `json:"delta"`
	// Meaningful is false when the suite is too small for the delta to be worth acting on. The
	// delta is still reported — hiding it would be its own kind of dishonesty — but a caller must
	// not present it as a finding when this is false.
	Meaningful bool `json:"meaningful"`
	// Verdict is a plain-language reading, and it declines to declare a winner on a tie or on a
	// suite too small to support one.
	Verdict string `json:"verdict"`
}

// Compare builds the ablation. Both arms must have run over the same cases.
func Compare(sub Result, mod ModelResult) Ablation {
	a := Ablation{
		SubstratePassed: sub.Passed, ModelPassed: mod.Passed,
		Cases: sub.Cases, Delta: mod.Passed - sub.Passed,
		Meaningful: sub.Cases >= minMeaningfulCases && sub.Cases == mod.Cases,
	}
	switch {
	case sub.Cases != mod.Cases:
		// Comparing two arms over different case sets is comparing nothing, the same refusal the
		// trend makes when a suite changes shape underneath it.
		a.Meaningful = false
		a.Verdict = "The two arms did not run over the same cases, so they cannot be compared."
	case !a.Meaningful:
		a.Verdict = "Too few graded cases for this comparison to mean anything yet."
	case a.Delta > 0:
		a.Verdict = fmt.Sprintf("Your model agreed with your team on %d more case(s) than the filter alone.", a.Delta)
	case a.Delta < 0:
		a.Verdict = fmt.Sprintf("Your model agreed with your team on %d fewer case(s) than the filter alone.", -a.Delta)
	default:
		a.Verdict = "Your model and the filter agreed with your team equally often."
	}
	return a
}

const noCasesNote = "No graded cases yet, so there is nothing to ask a model about. A suite is built " +
	"from decisions you have made — reinstating a suppressed finding, marking one a false positive, " +
	"or confirming a fix closed one."

const smallSuiteNote = "This suite is small, so the score moves a lot per case. It grows as you " +
	"correct the system — each reinstatement, suppression and confirmed fix adds a graded example."

// PromptFor renders the question put to the model. It is deliberately a package-level function so
// the exact wording is testable and reviewable rather than buried in a client.
//
// It gives the model the finding and NOTHING about the expected answer — not the human's verdict,
// not the reason they gave, not which bucket the case came from. A grader that can see the answer
// key is not measuring anything.
func PromptFor(f types.Finding) string {
	var b strings.Builder
	b.WriteString("You are triaging one security finding for this organisation.\n\n")
	fmt.Fprintf(&b, "Rule: %s\nTool: %s\nSeverity: %s\nLocation: %s\nTitle: %s\n",
		f.RuleID, f.Tool, f.Severity, f.Endpoint, f.Title)
	if d := strings.TrimSpace(f.Description); d != "" {
		fmt.Fprintf(&b, "Details: %s\n", clip(d, 1200))
	}
	b.WriteString("\nShould this finding be shown to the security team, or suppressed as noise?\n")
	b.WriteString("Answer with exactly one word: KEEP or SUPPRESS.")
	return b.String()
}

// ParseVerdict reads a model's reply. Anything that is not clearly one answer or the other is not
// an answer — a reply containing both words is ambiguous, and guessing which one it "meant" would
// manufacture agreement that the model did not express.
func ParseVerdict(reply string) (Verdict, bool) {
	up := strings.ToUpper(reply)
	keep, suppress := strings.Contains(up, "KEEP"), strings.Contains(up, "SUPPRESS")
	switch {
	case keep && !suppress:
		return Keep, true
	case suppress && !keep:
		return Suppress, true
	}
	return "", false
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// reasonFor renders why a case went unanswered, clipped so a provider that returns a wall of text
// cannot turn one failure into a page of output.
func reasonFor(err error) string {
	if err == nil {
		return "the model replied, but not with KEEP or SUPPRESS"
	}
	return clip(err.Error(), 300)
}
