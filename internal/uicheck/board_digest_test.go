package uicheck

import (
	"regexp"
	"strings"
	"testing"
)

// The board-report email schedule. Three server facts have to reach the owner, and each fails silently
// if the page drops it: whether anything will actually be sent, what went wrong last time, and the rule
// that the report only goes to seat holders. FAILS rather than skips when the file moves (§14.2 rule 6).

func TestBoardDigestControlRendersWhatTheServerSays(t *testing.T) {
	src := stripComments(frontendFile(t, "components", "settings", "board-digest-control.tsx"))
	for _, c := range []struct{ field, claim string }{
		{"s.delivery_note", "that a saved schedule will send, on a deployment with no mail relay where nothing " +
			"ever leaves — the owner tells the board to expect it and it never comes"},
		{"s.last_error", "that delivery is working after it failed, or after a recipient lost their seat — " +
			"'the board stopped getting it' is then discovered at the meeting"},
	} {
		// The CONDITION that renders it, not merely the name: a block disabled with `false &&` still
		// mentions the field inside it, which is how this guard first passed a page that showed nothing.
		if !strings.Contains(src, "{"+c.field+" && (") {
			t.Errorf("the board digest control never renders %s, so it implies %s", c.field, c.claim)
		}
	}
	// Send-now is gated on the server's own statement that delivery is configured, not a client guess.
	if !strings.Contains(src, "!s.delivery_configured") {
		t.Error("Send now must be disabled when the server says delivery is not configured")
	}
}

// Recipients are PICKED from seat holders. A free-text address box would invite exactly the input the
// server refuses (the report lists exploitable exposure; it goes only to people with a seat), and teach
// the owner the rule by error message rather than by the shape of the control.
func TestBoardDigestRecipientsArePickedFromSeats(t *testing.T) {
	src := stripComments(frontendFile(t, "components", "settings", "board-digest-control.tsx"))
	if regexp.MustCompile(`type=["']email["']`).MatchString(src) || regexp.MustCompile(`<input[^>]*placeholder=["'][^"']*@`).MatchString(src) {
		t.Error("the board digest control offers a typed email address; recipients must be picked from seat holders")
	}
	if !strings.Contains(src, "members.filter") || !strings.Contains(src, `type="checkbox"`) {
		t.Error("recipients must be chosen from the workspace's members")
	}
}
