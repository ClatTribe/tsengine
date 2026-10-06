package uicheck

import (
	"strings"
	"testing"
)

// The two-way ticket sync computes the one disagreement nobody else in the loop can see — a ticket
// closed while our re-test still finds the issue — and an unreadable ticket. Both must reach the reader:
// the first is the reason the sync exists, and the second must never be left looking "still open".
// FAILS rather than skips when the file moves (§14.2 rule 6).
func TestActivityRendersTicketDisagreementAndUnreadable(t *testing.T) {
	src := stripComments(frontendFile(t, "app", "(app)", "activity", "page.tsx"))
	for _, must := range []string{
		"t.closed_still_present",
		"tickets_closed_still_present",
		"still finds the issue",
		"tickets_unreadable",
		"not that",
		"Closing a ticket is not proof of a fix",
	} {
		if !strings.Contains(src, must) {
			t.Errorf("activity page no longer renders %q", must)
		}
	}
}
