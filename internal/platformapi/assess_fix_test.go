package platformapi

import (
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/internal/operate"
)

func TestAssess_FailingChecksCarryFixes(t *testing.T) {
	// Weak email (no DMARC/SPF/DKIM) + bare web (Domain set so the security.txt fix interpolates).
	r := assess(operate.DomainConfig{Name: "acme.com"}, webPosture{Domain: "acme.com", Reachable: true})

	for _, c := range r.Checks {
		if c.OK {
			if c.Fix != nil {
				t.Errorf("passing check %q must not carry a fix", c.Name)
			}
			continue
		}
		if c.Fix == nil || len(c.Fix.Snippets) == 0 || c.Fix.Summary == "" {
			t.Errorf("failing check %q must carry a fix with a snippet + summary, got %+v", c.Name, c.Fix)
			continue
		}
	}

	// The DMARC fix must contain the domain-specific record name.
	dmarc := findCheck(r.Checks, "DMARC enforcement")
	if dmarc == nil || dmarc.Fix == nil || !strings.Contains(dmarc.Fix.Snippets[0].Code, "_dmarc.acme.com") {
		t.Errorf("DMARC fix should reference _dmarc.acme.com, got %+v", dmarc)
	}
	// The security.txt fix must interpolate the domain.
	sectxt := findCheck(r.Checks, "Security contact (security.txt)")
	if sectxt == nil || sectxt.Fix == nil || !strings.Contains(sectxt.Fix.Snippets[0].Code, "security@acme.com") {
		t.Errorf("security.txt fix should reference acme.com, got %+v", sectxt)
	}
}

func TestAssess_HardenedHasNoFixes(t *testing.T) {
	r := assess(operate.DomainConfig{Name: "acme.com", DMARC: "reject", SPF: true, DKIM: true}, hardenedWeb())
	for _, c := range r.Checks {
		if c.Fix != nil {
			t.Errorf("hardened domain: check %q should have no fix", c.Name)
		}
	}
}

func findCheck(checks []assessCheck, name string) *assessCheck {
	for i := range checks {
		if checks[i].Name == name {
			return &checks[i]
		}
	}
	return nil
}
