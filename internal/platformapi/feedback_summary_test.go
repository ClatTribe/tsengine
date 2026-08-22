package platformapi

import (
	"testing"

	"github.com/ClatTribe/tsengine/pkg/platform"
)

func fb(verdict, evidence, key string) platform.Feedback {
	return platform.Feedback{TenantID: "t1", IssueKey: key, Verdict: verdict, Evidence: evidence}
}

// The evidence axis must be COUNTABLE. It was reaching tenanteval only as prose appended to a case's
// reason string, so "how often do customers say we failed to justify a finding?" meant regexing
// English — the same shape retest.ApplyReattack had before its disagreement fields existed.
func TestSummariseFeedback_CountsBothAxes(t *testing.T) {
	got := summariseFeedback([]platform.Feedback{
		fb(platform.FeedbackReal, platform.EvidenceInsufficient, "rule|sqli|/a"),
		fb(platform.FeedbackReal, platform.EvidenceSufficient, "rule|xss|/b"),
		fb(platform.FeedbackFalsePositive, "", "rule|noise|/c"),
	})
	if got.Total != 3 || got.Real != 2 || got.FalsePositive != 1 {
		t.Errorf("verdict axis miscounted: %+v", got)
	}
	if got.EvidenceInsufficient != 1 || got.EvidenceSufficient != 1 {
		t.Errorf("evidence axis miscounted: %+v", got)
	}
}

// "I could not understand this finding" is an ANSWER, not an absence of one. Folding unclear into
// either side would lose the one verdict that says the write-up failed rather than the detection.
func TestSummariseFeedback_UnclearIsItsOwnCount(t *testing.T) {
	got := summariseFeedback([]platform.Feedback{fb(platform.FeedbackUnclear, "", "rule|x|/a")})
	if got.Unclear != 1 {
		t.Errorf("unclear was not counted: %+v", got)
	}
	if got.Real != 0 || got.FalsePositive != 0 {
		t.Errorf("unclear was folded into a verdict it is not: %+v", got)
	}
}

// An UNANSWERED evidence question must be counted, not dropped. Otherwise a low insufficient count
// reads as approval when most people simply skipped that question.
func TestSummariseFeedback_UnansweredEvidenceIsVisible(t *testing.T) {
	got := summariseFeedback([]platform.Feedback{
		fb(platform.FeedbackReal, "", "rule|a|/a"),
		fb(platform.FeedbackReal, "", "rule|b|/b"),
	})
	if got.EvidenceUnanswered != 2 {
		t.Errorf("unanswered evidence questions vanished: %+v", got)
	}
}

// The actionable output: which issue draws the most "you did not show me why", worst first. That
// names the rule whose description to fix.
func TestSummariseFeedback_RanksTheWeakestExplanations(t *testing.T) {
	got := summariseFeedback([]platform.Feedback{
		fb(platform.FeedbackReal, platform.EvidenceInsufficient, "rule|weak|/a"),
		fb(platform.FeedbackReal, platform.EvidenceInsufficient, "rule|weak|/a"),
		fb(platform.FeedbackReal, platform.EvidenceInsufficient, "rule|other|/b"),
		fb(platform.FeedbackReal, platform.EvidenceSufficient, "rule|fine|/c"),
	})
	if len(got.WeakestExplanations) != 2 {
		t.Fatalf("expected two issues with insufficient evidence: %+v", got.WeakestExplanations)
	}
	if got.WeakestExplanations[0].IssueKey != "rule|weak|/a" || got.WeakestExplanations[0].Count != 2 {
		t.Errorf("not ranked worst-first: %+v", got.WeakestExplanations)
	}
	// A well-explained issue must not appear in a list of badly-explained ones.
	for _, w := range got.WeakestExplanations {
		if w.IssueKey == "rule|fine|/c" {
			t.Errorf("an issue whose evidence satisfied the reader was listed as weak: %+v", w)
		}
	}
}

// Empty is zeros, not absence: a tenant who has given no feedback must read as "none yet" rather
// than as a clean bill.
func TestSummariseFeedback_EmptyIsZeroed(t *testing.T) {
	got := summariseFeedback(nil)
	if got.Total != 0 || len(got.WeakestExplanations) != 0 {
		t.Errorf("empty feedback invented something: %+v", got)
	}
}
