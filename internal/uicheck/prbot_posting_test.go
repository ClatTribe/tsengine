package uicheck

import (
	"strings"
	"testing"
)

// The PR-bot panel renders the SERVER's posting status — whether reviews actually land in the PR
// and, when not, the reason naming the first missing piece — and lets the customer record the
// App installation id. Re-deriving the status client-side would let the page disagree with the
// gate; hiding the reason would send the reader to the wrong fix.
//
// FAILS rather than skips when a file moves (§14.2 rule 6) — frontendFile fatals.
func TestPRBotPanelShowsPostingStatusAndTakesTheInstallationID(t *testing.T) {
	comp := stripComments(frontendFile(t, "components", "settings", "pr-bot-settings.tsx"))
	for _, want := range []string{"initial.posting_live", "initial.not_posting_reason", "installationId", "Not posting to pull requests yet"} {
		if !strings.Contains(comp, want) {
			t.Errorf("the PR-bot panel does not render %q — the customer cannot tell whether reviews reach the PR, or why not", want)
		}
	}
	action := stripComments(frontendFile(t, "app", "(app)", "settings", "actions.ts"))
	if !strings.Contains(action, "installationId") {
		t.Error("the save action drops the installation id before it reaches the server")
	}
	types := stripComments(frontendFile(t, "lib", "types.ts"))
	if !strings.Contains(types, "not_posting_reason") {
		t.Error("PRBotSettings does not declare not_posting_reason")
	}
}
