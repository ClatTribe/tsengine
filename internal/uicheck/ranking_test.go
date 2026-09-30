package uicheck

import (
	"strings"
	"testing"
)

// The issue list is ORDERED by evidence (crossdetect.RankIssue), which now moves an issue across
// severity bands. An order a reader cannot account for reads as arbitrary — or worse, as severity with
// mistakes in it — so the page must show the server's reasons. FAILS rather than skips when the file
// moves (§14.2 rule 6).
func TestIssuesPageExplainsTheRanking(t *testing.T) {
	page := stripComments(frontendFile(t, "app", "(app)", "issues", "page.tsx"))

	if strings.Count(page, "<RankWhy factors={issue.rank_factors}") < 2 {
		t.Error("the issues page must render the server's rank_factors on BOTH the lead card and every row — " +
			"evidence now reorders across severity, and an unexplained order reads as a bug")
	}
	if !strings.Contains(page, "lowered:") {
		t.Error("a factor that LOWERED the rank (a WAF blocking the attack) must say so, or a mitigation " +
			"reads as a fix")
	}
	// The order is decided server-side; a client that recomputed it would eventually disagree with the
	// list it sorts.
	for _, bad := range []string{"RankIssue(", "exploitabilityBoost", "points * ", "severityBase("} {
		if strings.Contains(page, bad) {
			t.Errorf("the issues page must render the server's ranking, never recompute it (found %q)", bad)
		}
	}
}
