package uicheck

import (
	"strings"
	"testing"
)

// The Okta configuration-posture sync is reachable from the Okta connection row, and its result
// renders the UNREAD count beside the finding count — a token without okta.policies.read reads
// nothing about the policies, and "0 posture issues" would then be a statement about the token,
// not the org.
//
// FAILS rather than skips when a file moves (§14.2 rule 6) — frontendFile fatals.
func TestOktaPostureSyncIsMountedAndShowsWhatCouldNotBeRead(t *testing.T) {
	page := stripComments(frontendFile(t, "app", "(app)", "settings", "page.tsx"))
	if !strings.Contains(page, `c.kind === "okta" && <OktaPostureSync />`) {
		t.Error("the Settings page does not mount the Okta posture sync on the Okta connection row")
	}
	comp := stripComments(frontendFile(t, "components", "settings", "okta-posture-sync.tsx"))
	if !strings.Contains(comp, "could not be read") || !strings.Contains(comp, "r.unread") {
		t.Error("the Okta posture control does not render the unread count — zero findings would read as a hardened org when the token simply lacks the read scope")
	}
	action := stripComments(frontendFile(t, "app", "(app)", "settings", "actions.ts"))
	if !strings.Contains(action, "r.unread") {
		t.Error("the sync action drops the server's unread map before the component can show it")
	}
}
