package uicheck

import (
	"strings"
	"testing"
)

// The vendor register's honesty lives in three fields the server computes and the screen can quietly
// drop. FAILS rather than skips when a file moves (§14.2 rule 6).
func TestVendorRegisterRendersTheAdmissionsNotJustTheCount(t *testing.T) {
	src := frontendFile(t, "components", "posture", "vendor-register.tsx")

	for _, c := range []struct{ field, claim string }{
		{"s.detail", "a count with no statement of what it means — the server writes the sentence that " +
			"separates an EMPTY register from a clean one, and a company with nothing written down " +
			"looks identical to one with no vendor risk until it is said out loud"},
		{"never_reviewed", "that every recorded vendor has been looked at, when a register's whole " +
			"purpose is to show which relationships nobody has reviewed"},
		{"unowned", "that every vendor has somebody accountable for it — the first thing an auditor " +
			"asks, and the field is empty precisely because we refuse to invent an owner"},
	} {
		if !strings.Contains(src, c.field) {
			t.Errorf("the vendor register never references %q.\n\nWithout it the page asserts %s.", c.field, c.claim)
		}
	}

	// Per row, the two admissions are stated in words rather than left as blank cells a reader fills
	// in optimistically.
	if !strings.Contains(src, "No named owner") || !strings.Contains(src, "never reviewed") {
		t.Error("a vendor row leaves 'unowned' or 'never reviewed' as an empty cell. A blank reads as " +
			"'nothing to say here'; both are facts about the relationship and are said.")
	}
}

// The register must not publish a single vendor-compliance score. It would blend "we hold their SOC 2
// report" with "nobody has looked at this since 2024", and it would RISE as a customer recorded fewer
// vendors — the same defect internal/training refuses by name.
func TestVendorRegisterPublishesNoPortfolioScore(t *testing.T) {
	src := stripComments(frontendFile(t, "components", "posture", "vendor-register.tsx"))
	if strings.Contains(src, "toFixed") && strings.Contains(src, "%") {
		t.Error("the vendor register renders a percentage — the counts are kept separate because a " +
			"single figure over them climbs as a customer records fewer vendors")
	}
	for _, bad := range []string{"/ s.total", "/ data.vendors.length"} {
		if strings.Contains(src, bad) {
			t.Errorf("the vendor register divides by the register size (%q), which is the score it "+
				"must not publish", bad)
		}
	}
}
