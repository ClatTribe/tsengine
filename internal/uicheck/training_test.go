package uicheck

import (
	"regexp"
	"strings"
	"testing"
)

// The training page is where an honest programme is easiest to render dishonestly: every product in
// this category shows one big completion percentage, and that is precisely the number internal/
// training refuses to compute. These guards hold the screen to the package's refusals.
//
// FAILS rather than skips when a file moves (§14.2 rule 6) — frontendFile fatals.

// THE HEADLINE REFUSAL, at the screen. A single figure spanning "we showed them the content and they
// confirmed" and "somebody says it happened elsewhere" rises as a customer asserts more and
// evidences less. The server publishes no such number; the page must not compute one either.
func TestTrainingPagePublishesNoCombinedCompletionRate(t *testing.T) {
	src := stripComments(frontendFile(t, "app", "(app)", "training", "page.tsx"))

	// Any arithmetic that divides one training count by the assignment total is that number.
	rate := regexp.MustCompile(`(complete_delivered|complete_attested|done\.length)[^;\n]*[/][^;\n]*(assignments|statuses\.length|sts\.length)`)
	if rate.MatchString(src) {
		t.Error("the training page computes a completion rate.\n\n" +
			"internal/training deliberately emits no combined figure: delivered and attested are " +
			"different evidence, and one percentage over both climbs as a customer records more " +
			"second-hand claims and reads less content.")
	}
	if strings.Contains(src, "toFixed") && strings.Contains(src, "%") {
		t.Error("the training page renders a percentage — see above; the two tiers are counted separately.")
	}
	// Both counts must actually be rendered, or "separately" becomes "one of them".
	for _, f := range []string{"complete_delivered", "complete_attested"} {
		if !strings.Contains(src, f) {
			t.Errorf("the training page never renders %s — the two tiers are only kept apart if BOTH appear", f)
		}
	}
}

// An empty roster is not a trained workforce, and a record for somebody off the roster counts
// towards nothing. Both are server-computed and both are invisible unless the page says so.
func TestTrainingPageRendersTheHonestyFields(t *testing.T) {
	src := stripComments(frontendFile(t, "app", "(app)", "training", "page.tsx"))
	for _, c := range []struct{ field, claim string }{
		{"no_roster", "that a programme with nobody on the roster is a finished one — with no denominator " +
			"there is no completion to report, and the zero counts read as success"},
		{"off_roster", "that every recorded completion counts, when one entered against an address the " +
			"roster does not know counts towards nothing — and whoever entered it would watch the " +
			"summary not move and assume it landed"},
		{"s.detail", "the numbers with no statement of what they mean; the server writes the sentence " +
			"that separates an empty programme from a complete one"},
		{"roster_sources", "one roster, when an HRIS roster and the people who happen to have logged " +
			"into this product are very different claims about who works at a company"},
	} {
		if !strings.Contains(src, c.field) {
			t.Errorf("the training page never references %q.\n\nWithout it the page asserts %s.", c.field, c.claim)
		}
	}
}

// "We rendered this and you confirmed" and "somebody says you did this elsewhere" must never look
// like the same tick, and the confirm button must not claim more than it can.
func TestTrainingReaderDistinguishesTheTiersAndDoesNotClaimAPass(t *testing.T) {
	src := frontendFile(t, "components", "training", "module-reader.tsx")

	if !strings.Contains(src, "attested_external") {
		t.Error("the module reader never checks the tier, so training recorded second-hand renders " +
			"identically to content the person actually read here")
	}
	if !strings.Contains(src, "It is not a test") {
		t.Error("the confirm control does not say what the record actually claims. It attests that the " +
			"text was on screen and the person said so — calling that a pass would assert an " +
			"assessment nobody administered.")
	}
	for _, banned := range []string{"Passed", "passed the", "Certified", "certificate"} {
		if strings.Contains(src, banned) {
			t.Errorf("the module reader says %q — reading a page is not a pass, a certification, or a "+
				"certificate, and an audit record built on that wording overstates what happened", banned)
		}
	}
}

// The second-hand form must ask for the two things that make a second-hand claim checkable: who
// delivered it, and when it really happened.
func TestExternalRecordFormAsksWhoDeliveredItAndWhen(t *testing.T) {
	src := frontendFile(t, "components", "training", "record-external.tsx")
	if !strings.Contains(src, `name="provider"`) {
		t.Error(`no provider field: "trained externally" without naming the source is not a fact anybody can check`)
	}
	if !strings.Contains(src, `name="on"`) {
		t.Error("no date field: currency is measured from the completion date, so recording an old " +
			"course as if it happened today silently restarts a clock that has already run out")
	}
	if !strings.Contains(src, "second-hand") {
		t.Error("the form does not tell the person entering it that this is weaker evidence, counted " +
			"separately from training completed here")
	}
}
