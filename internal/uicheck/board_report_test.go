package uicheck

import (
	"strings"
	"testing"
)

// The board report is the page most likely to be read without context, so its honesty lives in what
// it renders: the server's headline and caveats verbatim, "not graded" as its own state, the unscanned
// assets named — and no single score, which would rise as a customer connected less.
func TestBoardPageRendersTheServersReportAndItsCaveats(t *testing.T) {
	page := stripComments(frontendFile(t, "app", "(app)", "board", "page.tsx"))
	for _, want := range []struct{ s, why string }{
		{"api.boardReport()", "the page does not read the server's report"},
		{"{r.headline}", "the headline (which carries the coverage caveat) is not rendered"},
		{"r.caveats.map", "what the numbers do not say is not rendered"},
		{`"Not graded"`, "an ungradeable objective has no state of its own"},
		{"never scanned", "unscanned assets are not named"},
		{"{v.reason}", "the objective's reason is not rendered verbatim"},
	} {
		if !strings.Contains(page, want.s) {
			t.Errorf("board page: %s (missing %q)", want.why, want.s)
		}
	}
	for _, banned := range []string{"score", "Score", "grade:"} {
		if strings.Contains(page, banned) {
			t.Errorf("the board page must not print a single %q — a blended number rises as a customer connects less", banned)
		}
	}
}
