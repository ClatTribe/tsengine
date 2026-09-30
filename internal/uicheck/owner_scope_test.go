package uicheck

import (
	"strings"
	"testing"
)

// The server now refuses a MEMBER the owner's acts (internal/platformapi/owner_scope.go): resuming
// halted automation, restoring a quarantined connection, accepting a risk, adding an exclusion rule,
// every setting. These pages call those endpoints through server actions whose failures are swallowed
// into a refresh (useAction) — so a control offered to a member who will be refused does NOTHING
// visible when clicked, which reads as a broken page. Each control must therefore be gated on the
// role the server gates on, and each page must pass it. FAILS rather than skips when a file moves.
func TestOwnerOnlyControlsAreNotOfferedToMembers(t *testing.T) {
	checks := []struct {
		path []string
		want []string
		why  string
	}{
		{
			[]string{"components", "settings", "kill-switch.tsx"},
			[]string{"halted ? canResume : canHalt"},
			"the kill-switch must offer RESUME only to whoever may resume (the owner) while still letting a member halt",
		},
		{
			[]string{"components", "settings", "quarantine-button.tsx"},
			[]string{"quarantined && !canRestore"},
			"a member may quarantine a connection but restoring it is the owner's",
		},
		{
			[]string{"app", "(app)", "settings", "page.tsx"},
			[]string{"canResume={isOwner}", "canRestore={isOwner}", "Settings are changed by the workspace owner"},
			"the settings page must pass the owner flag and tell a member their saves will be refused",
		},
		{
			[]string{"components", "issues", "issue-actions.tsx"},
			[]string{`REASONS.filter((r) => r.value === "false_positive")`},
			"a member may mark a false positive; accepting a risk must not be offered to them",
		},
		{
			[]string{"app", "(app)", "issues", "page.tsx"},
			[]string{"canDecideRisk={isOwner}", "canAdd={isOwner}"},
			"the issues page must pass the owner flag to the ignore control and the exclusion manager",
		},
		{
			[]string{"components", "issues", "exclusion-rules.tsx"},
			[]string{"!canAdd"},
			"adding an exclusion rule must not be offered to a member",
		},
		{
			[]string{"components", "risks", "decide-risk.tsx"},
			[]string{`TREATMENTS.filter((t) => t.value !== "accept")`},
			"a member must not be offered 'accept' on a risk",
		},
		{
			[]string{"app", "(app)", "risks", "page.tsx"},
			[]string{"canAccept={isOwner}"},
			"the risk register must pass the owner flag to the decision control",
		},
	}
	for _, c := range checks {
		src := stripComments(frontendFile(t, c.path...))
		for _, w := range c.want {
			if !strings.Contains(src, w) {
				t.Errorf("%s: %s (missing %q)", strings.Join(c.path, "/"), c.why, w)
			}
		}
	}
}
