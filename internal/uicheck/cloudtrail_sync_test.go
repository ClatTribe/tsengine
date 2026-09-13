package uicheck

import (
	"strings"
	"testing"
)

// The CloudTrail poll is reachable from the AWS connection row, and its result renders whether the
// window was PARTIALLY read beside the finding count — a busy account can write more events than
// one read examines, and "0 threats" over a partial window is a statement about the read, not the
// account.
//
// FAILS rather than skips when a file moves (§14.2 rule 6) — frontendFile fatals.
func TestCloudTrailSyncIsMountedAndShowsAPartialRead(t *testing.T) {
	page := stripComments(frontendFile(t, "app", "(app)", "settings", "page.tsx"))
	if !strings.Contains(page, `c.kind === "aws" && <CloudTrailSync />`) {
		t.Error("the Settings page does not mount the CloudTrail sync on the AWS connection row")
	}
	comp := stripComments(frontendFile(t, "components", "settings", "cloudtrail-sync.tsx"))
	if !strings.Contains(comp, "could not be read") || !strings.Contains(comp, "r.unread") {
		t.Error("the CloudTrail control does not render the partial-read note — zero threats would read as a quiet account when the read stopped early")
	}
	action := stripComments(frontendFile(t, "app", "(app)", "settings", "actions.ts"))
	if !strings.Contains(action, "r.unread") || !strings.Contains(action, "syncCloudEvents") {
		t.Error("the sync action drops the server's unread map before the component can show it")
	}
}
