package uicheck

import (
	"strings"
	"testing"
)

// The roster invite creates accounts for people who did not ask, in bulk. The server names who it
// will NOT seat and why; this holds the panel to rendering that, showing the plan before the act,
// and never offering a role — a bulk act must not be able to hand the whole company the estate.
//
// FAILS rather than skips when a file moves (§14.2 rule 6) — frontendFile fatals.
func TestInviteRosterShowsThePlanAndNamesWhoIsNotSeated(t *testing.T) {
	src := stripComments(frontendFile(t, "components", "settings", "invite-roster.tsx"))

	// The plan before the act: the button that seats people renders only from a fetched plan.
	if !strings.Contains(src, `fetch("/api/team/invite-roster", { cache: "no-store" })`) {
		t.Error("the panel does not fetch the preview (GET) — the owner would seat people from a number they never saw")
	}
	if !strings.Contains(src, "plan.to_invite.length > 0 && !plan.no_roster") {
		t.Error("the run button is not gated on a non-empty plan over a real roster")
	}
	// Who is NOT invited, named with the server's reason — in both the plan and the result.
	for _, field := range []string{"plan.skipped", "plan.already_seated", "result.skipped", "result.already_seated", "result.failed"} {
		if !strings.Contains(src, field) {
			t.Errorf("the panel never renders %s — the people not seated would be folded into a count", field)
		}
	}
	if !strings.Contains(src, "s.reason") {
		t.Error("skipped people are listed without the server's reason")
	}
	// The server's own sentences, not a paraphrase.
	for _, f := range []string{"plan.detail", "result.note"} {
		if !strings.Contains(src, f) {
			t.Errorf("the panel does not render %s", f)
		}
	}
	// No role control. The server mints employee seats only; a select here would imply otherwise.
	for _, banned := range []string{"<select", `"member"`, `"auditor"`, "role:"} {
		if strings.Contains(src, banned) {
			t.Errorf("the roster panel contains %q — it must not offer a role; the bulk act seats employees only", banned)
		}
	}
	// Credentials: shown only for people the platform could not email, and said to be shown once.
	if !strings.Contains(src, "!i.emailed") || !strings.Contains(src, "shown once") {
		t.Error("temp passwords must render only for un-emailed invites and be marked as shown once")
	}
}

func TestTeamSectionMountsTheRosterInviteForOwnersOnly(t *testing.T) {
	src := stripComments(frontendFile(t, "components", "settings", "team-section.tsx"))
	if !strings.Contains(src, "{canInvite && <InviteRoster />}") {
		t.Error("the Team section does not mount the roster invite behind the owner gate")
	}
}
