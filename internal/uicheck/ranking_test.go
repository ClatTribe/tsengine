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

// Choke points were computed by the server and returned by GET /v1/attack-paths for months while the
// page never read the field — the highest-leverage fix on the page ("one change cuts N routes") was
// computed and discarded at the last step. These pin the reader half.
func TestAttackPathsPageShowsChokePoints(t *testing.T) {
	page := stripComments(frontendFile(t, "app", "(app)", "attack-paths", "page.tsx"))

	for _, want := range []struct{ field, why string }{
		{"choke_points", "the page never reads choke_points — the fix that cuts several paths at once is invisible"},
		{"c.why", "a choke point is shown without the server's own reason for its leverage"},
		{"c.paths", "a choke point is shown without how many paths run through it — the whole point of it"},
	} {
		if !strings.Contains(page, want.field) {
			t.Errorf("attack-paths page never renders %s: %s", want.field, want.why)
		}
	}
}
