package uicheck

import (
	"strings"
	"testing"
)

// An accepted risk now has a review date (platform.IgnoreRule.ExpiresAt). The server returns a lapsed
// acceptance to the active list; if the page did not say WHY the issue came back, it would read as a
// suppression that silently failed. FAILS rather than skips when a file moves (§14.2 rule 6).
func TestIssuesPageShowsTheRiskDecisionBehindEachRow(t *testing.T) {
	page := stripComments(frontendFile(t, "app", "(app)", "issues", "page.tsx"))
	for _, want := range []struct{ s, why string }{
		{"acceptances", "the page never reads the server's acceptances map"},
		{"<AcceptanceNote decision={decision}", "rows never render the decision behind them"},
		{"Risk acceptance lapsed on", "a lapsed acceptance returns to the list without saying why"},
		{"with no review date", "an older acceptance with no review date is not flagged"},
	} {
		if !strings.Contains(page, want.s) {
			t.Errorf("issues page: %s (missing %q)", want.why, want.s)
		}
	}
}

// The review period must be a VISIBLE choice sent to the server, not a default applied behind the
// person's back — and a false positive, which has nothing to review, must not be asked for one.
func TestIgnoreControlSendsAVisibleReviewPeriod(t *testing.T) {
	ctl := stripComments(frontendFile(t, "components", "issues", "issue-actions.tsx"))
	if !strings.Contains(ctl, "REVIEW_DAYS.map") {
		t.Error("the ignore control offers no review period — the date would be a silent server default")
	}
	if !strings.Contains(ctl, `reason !== "false_positive"`) {
		t.Error("a false positive must not be asked for a review date")
	}
	if !strings.Contains(ctl, "needsReview ? reviewDays : undefined") {
		t.Error("the chosen review period is not sent to the server")
	}
}
