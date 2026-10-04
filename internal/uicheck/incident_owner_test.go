package uicheck

import (
	"strings"
	"testing"
)

// The incident queue says who an alert is routed to, in the server's three states. Collapsing them is the
// defect: showing nothing for an unowned asset hides the routing gap, and showing "unowned" for an incident
// with no asset at all accuses a scoping failure the data cannot support. FAILS rather than skips when the
// file moves (§14.2 rule 6).
func TestIncidentOwnerBadgeKeepsTheThreeStates(t *testing.T) {
	src := stripComments(frontendFile(t, "app", "(app)", "incidents", "page.tsx"))
	if !strings.Contains(src, "<OwnerBadge incident={i} />") {
		t.Fatal("the incident row never renders OwnerBadge — who the alert is routed to is computed and not shown")
	}
	if !strings.Contains(src, "if (!i.asset_id) return null;") {
		t.Error("an incident with no asset must render nothing about ownership: unknown is not unowned")
	}
	if !strings.Contains(src, "unowned asset") {
		t.Error("an asset with no owner must be said to be unowned — an alert with no route to a person is the gap to close")
	}
}
