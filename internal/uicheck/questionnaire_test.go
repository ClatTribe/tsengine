package uicheck

import (
	"strings"
	"testing"
)

// questionnaire_test.go guards the reader half of the two-tier security questionnaire.
//
// The corpus answers 52 questions two ways — 35 from live evidence, 17 by a named human — and the
// entire value of the split is that a reader can tell them apart. Rendered alike, "a scanner
// confirmed this" and "somebody typed yes" become the same claim, which is exactly the
// false-confidence the evidenced tier exists to avoid.

func TestQuestionnairePageSeparatesTheTwoEvidenceTiers(t *testing.T) {
	src := frontendFile(t, "app", "(app)", "compliance", "questionnaire", "page.tsx")

	if !strings.Contains(src, "observed_yes") {
		// yes/total mixes the tiers and is wrong in both directions: adding attested questions
		// makes the figure FALL although nothing got worse, and answering them makes it RISE on
		// typed assertions while the label still claims the answers came from evidence.
		t.Error("the percentage is not built from observed_yes, so it mixes evidenced answers with " +
			"typed ones — a number that rises when a customer asserts more and falls when questions " +
			"are added means neither")
	}
	if !strings.Contains(src, "questions we can evidence") {
		t.Error("the percentage does not name its denominator. A bare percentage over a mixed corpus " +
			"reads as a grade for the whole document")
	}
	if !strings.Contains(src, "needs_you") && !strings.Contains(src, "needsYou") {
		t.Error("the page never reads needs_you. A question awaiting OUR answer is not one waiting on " +
			"an integration, and folding them together tells the reader to fix the wrong thing")
	}
	if !strings.Contains(src, "no evidence source connected") {
		t.Error("the 'not assessed' admission is missing — a mostly-unanswered questionnaire must look " +
			"mostly unanswered")
	}
	if !strings.Contains(src, "attested_by") {
		t.Error("the page does not render who stated an attested answer, so an assertion is " +
			"indistinguishable from something we observed")
	}
}

func TestAttestControlOffersBothAnswers(t *testing.T) {
	src := frontendFile(t, "components", "compliance", "attest-answer.tsx")

	// A questionnaire that could only say yes would be a form with one possible outcome, and a
	// vendor honestly reporting a gap is giving the buyer exactly what they asked for.
	if !strings.Contains(src, "No, not yet") {
		t.Error("the answer control offers no way to say no")
	}
	if !strings.Contains(src, "answer(false)") {
		t.Error("nothing sends in_place=false, so a 'no' could never be recorded")
	}
	// The person is told what happens with their name, because the answer is published to a
	// stranger under it.
	if !strings.Contains(src, "who stated it") {
		t.Error("the control does not tell the answerer that their name is published with the answer")
	}
}
