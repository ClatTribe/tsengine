package uicheck

import (
	"strings"
	"testing"
)

// The fix plan is only useful if it is the SERVER's plan. The order and grouping come from
// grc.BuildRoadmap — the same ones the VAPT report and the bulk-PR engine use — so a page that
// re-sorted or re-grouped would describe different work from the report and the pull requests.
// And its two honesty caveats (no effort estimates; delivered is not fixed) live in the server's
// note, so the note must be rendered, not paraphrased. FAILS rather than skips when a file moves.
func TestFixPlanPageRendersTheServersPlan(t *testing.T) {
	page := stripComments(frontendFile(t, "app", "(app)", "fixes", "page.tsx"))
	for _, want := range []struct{ s, why string }{
		{"api.fixPlan()", "the page does not read the server's plan"},
		{"{plan.note}", "the server's caveat (no effort estimates, delivered is not fixed) is not rendered"},
		{"s.state.not_proposed > 0", "the prepare control is not gated on work that has no fix yet"},
		{"fix did not hold", "a fix a re-scan contradicted is not called out"},
		{"the next scan confirms", "a delivered fix is presented as done"},
		{"unowned", "an unowned asset is not flagged"},
		{"Unconfirmed", "an unproven step is not flagged for validation"},
	} {
		if !strings.Contains(page, want.s) {
			t.Errorf("fixes page: %s (missing %q)", want.why, want.s)
		}
	}
	for _, banned := range []string{".sort(", "effort", "hours", "days to"} {
		if strings.Contains(page, banned) {
			t.Errorf("fixes page must not %q — the order is the server's and there are no effort estimates", banned)
		}
	}
	btn := stripComments(frontendFile(t, "components", "fixes", "prepare-step.tsx"))
	if !strings.Contains(btn, "for approval") || !strings.Contains(btn, "r.detail") {
		t.Error("the prepare control must say it goes for approval and show the server's own result line")
	}
}
