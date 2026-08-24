package api

import (
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/internal/asset"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// TestCoverageGaps_KeepsTheAuthzDisclosure guards the composition.
//
// api has TWO things it does not check: object/function-level authorization (it needs two real
// identities) and KEV-listed CVEs that nuclei ships no template for. The threat-informed half was
// missing, and the natural fix — "add the CoverageGaps reporter, web/ip/domain pattern" — REPLACES
// this method and silently deletes the authorization disclosure. That trades one silent gap for
// another, which is why this asserts the authz gap survives rather than just asserting the new one
// appears.
func TestCoverageGaps_KeepsTheAuthzDisclosure(t *testing.T) {
	h := NewHandler()
	findings := []types.Finding{{
		RuleID:   specFoundRule,
		ToolArgs: map[string]string{"operations": "17"},
	}}

	gaps := h.CoverageGaps(types.Asset{Type: types.AssetAPI, Target: "https://api.example.test"}, findings)

	var sawAuthz bool
	for _, g := range gaps {
		if g.RuleID == authzGapRule {
			sawAuthz = true
			if !strings.Contains(g.Title, "17") {
				t.Errorf("the authz disclosure lost its operation count: %q — a gap announced without "+
					"the number it turns on reads as boilerplate", g.Title)
			}
		}
		// Whatever the source, a coverage finding asserts an ABSENCE OF TESTING and never a
		// vulnerability, so it must stay informational and carry the coverage prefix.
		if !strings.HasPrefix(g.RuleID, asset.CoverageRulePrefix) {
			t.Errorf("gap %q lacks the coverage:: prefix — internal/coverage would count it as a "+
				"finding, so admitting a gap would RAISE the numbers describing how well the asset "+
				"was covered", g.RuleID)
		}
		if g.Severity != types.SeverityInfo {
			t.Errorf("gap %q is %s, want info: a check that did not run has no evidence for a "+
				"severity", g.RuleID, g.Severity)
		}
	}
	if !sawAuthz {
		t.Error("the authorization disclosure is GONE. Composing the threat-informed gaps must not " +
			"replace it — an asset can have more than one thing it did not check.")
	}
}

// TestCoverageGaps_SilentWithNothingToDeclare: no spec ingested and no observed software means
// there is nothing concrete to point at, and a gap announced anyway is boilerplate.
func TestCoverageGaps_SilentWithNothingToDeclare(t *testing.T) {
	h := NewHandler()
	if got := h.CoverageGaps(types.Asset{Type: types.AssetAPI}, nil); len(got) != 0 {
		t.Errorf("declared %d gap(s) with no spec and no observations: %+v", len(got), got)
	}
}
