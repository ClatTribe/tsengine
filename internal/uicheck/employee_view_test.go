package uicheck

import (
	"strings"
	"testing"
)

// THE EMPLOYEE'S VIEW OF THE TWO PAGES THE SEAT MAY OPEN. The server cuts /v1/training and
// /v1/program to that person (only their rows; only published policies) and says so with
// scope === "self". The pages must BRANCH on that, not on the size of what came back — a company of
// one and a colleague's view are the same list — and the employee branch must render none of the
// administration controls, because every one of them is an act the API refuses this seat and a
// control that fails on click reads as a broken page rather than a scoped one.
//
// FAILS rather than skips when a file moves (§14.2 rule 6) — frontendFile fatals.

// employeeBranch returns the source of the `scope === "self"` early-return branch: from the test
// to the owner's own `return (` that follows it (kept at two-space indent).
func employeeBranch(t *testing.T, page, marker string) string {
	t.Helper()
	i := strings.Index(page, marker)
	if i < 0 {
		t.Fatalf("the page does not branch on %s; an employee would be shown the owner's frame — "+
			"tabs to refused pages and controls the API refuses this seat — around the one section "+
			"that is theirs", marker)
	}
	branch := page[i:]
	end := strings.Index(branch, "\n  return (")
	if end < 0 {
		t.Fatal("cannot find the end of the employee branch — keep the owner's `return (` at two-space indent")
	}
	return branch[:end]
}

func TestTrainingPageGivesAnEmployeeOnlyTheirOwnModules(t *testing.T) {
	page := stripComments(frontendFile(t, "app", "(app)", "training", "page.tsx"))
	branch := employeeBranch(t, page, `data.scope === "self"`)

	for _, banned := range []string{"RecordExternal", "PageTabs", "byPerson", "off_roster", "no_roster", "roster_sources"} {
		if strings.Contains(branch, banned) {
			t.Errorf("the employee branch renders %s — an owner's control or an owner's number, "+
				"refused to this seat by the API", banned)
		}
	}
	if !strings.Contains(branch, "ModuleReader") {
		t.Error("the employee branch does not render the module reader — the one thing the seat exists for")
	}
}

func TestProgramPageGivesAnEmployeeOnlyPublishedPoliciesToAcknowledge(t *testing.T) {
	page := stripComments(frontendFile(t, "app", "(app)", "program", "page.tsx"))
	branch := employeeBranch(t, page, `scope === "self"`)

	for _, banned := range []string{"seedProgram", "PageTabs", "summary.published", "ack_coverage_pct", "summary.draft"} {
		if strings.Contains(branch, banned) {
			t.Errorf("the employee branch renders %s — an owner's control or an owner's number", banned)
		}
	}
	if !strings.Contains(branch, "PolicyRow") {
		t.Error("the employee branch offers no policy rows — no way to acknowledge, the one act the seat is for")
	}
	// The row itself must not render the publish control for a reader, whatever status arrives:
	// the server filters drafts today, but the row is the last line and must refuse on its own.
	if !strings.Contains(page, "reader ? null : <PublishButton") {
		t.Error("PolicyRow renders PublishButton to a reader when a draft reaches it")
	}
}
