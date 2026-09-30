package uicheck

import (
	"strings"
	"testing"
)

// "Is exposure going down?" was answered; "is that GOOD?" was computed by the server (the objective
// verdict) and read by no page. The verdict has THREE states and the third is the one a lazy render
// gets wrong: a series too short, mixed or unmeasured to grade is NOT a miss, and rendering it as one
// accuses a programme of failing a target nobody could yet measure. FAILS rather than skips.
func TestActivityPageGradesTheTrendAgainstTheObjective(t *testing.T) {
	page := stripComments(frontendFile(t, "app", "(app)", "activity", "page.tsx"))
	if !strings.Contains(page, "<ExposureObjective verdict={trend.objective}") {
		t.Error("the activity page does not render the objective verdict the server computes")
	}
	c := stripComments(frontendFile(t, "components", "activity", "exposure-objective.tsx"))
	for _, want := range []struct{ s, why string }{
		{"{verdict.reason}", "the verdict's reason is not rendered verbatim — the failing clause lives in it"},
		{"verdict.target", "the target is not restated beside the actual"},
		{`"Not graded"`, "an ungradeable series has no state of its own"},
		{"verdict.gradeable", "met/not-met is shown without checking the series could be graded at all"},
		{"setExposureObjective(", "there is no way to set the objective the verdict is graded against"},
	} {
		if !strings.Contains(c, want.s) {
			t.Errorf("exposure objective: %s (missing %q)", want.why, want.s)
		}
	}
}
