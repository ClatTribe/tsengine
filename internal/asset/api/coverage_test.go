package api

import (
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/internal/asset"
	"github.com/ClatTribe/tsengine/pkg/types"
)

func specFinding(ops string) types.Finding {
	return types.Finding{
		RuleID:   specFoundRule,
		Severity: types.SeverityInfo,
		ToolArgs: map[string]string{"operations": ops},
	}
}

// The disclosure exists because a scan that never tested authorization and a scan that
// tested it and found nothing render identically. If this stops firing, that silence
// comes back.
func TestAuthorizationGapIsDeclaredWhenOperationsExist(t *testing.T) {
	h := NewHandler()
	got := h.CoverageGaps(types.Asset{Type: types.AssetAPI}, []types.Finding{specFinding("6")})
	if len(got) != 1 {
		t.Fatalf("got %d gaps, want 1 — a scan with 6 declared operations tested none of them for authorization", len(got))
	}
	g := got[0]
	if !asset.IsCoverageGap(g) {
		t.Errorf("rule %q is not under the coverage prefix; internal/coverage would count it as a security finding "+
			"and admitting a gap would RAISE the numbers describing how well the asset was covered", g.RuleID)
	}
	if g.Severity != types.SeverityInfo {
		t.Errorf("severity %s — a check that did not run has no evidence for a severity", g.Severity)
	}
	if !strings.Contains(g.Title, "6") {
		t.Errorf("title %q does not name the operation count that makes the offer concrete", g.Title)
	}
	if g.ToolArgs["owasp_api"] != "API1,API5" {
		t.Errorf("owasp_api = %q, want API1,API5 so the per-item scoreboard can read it", g.ToolArgs["owasp_api"])
	}
	if g.ToolArgs["remediation"] == "" {
		t.Error("no remediation — a disclosure without the remedy is a caveat people learn to scroll past")
	}
}

// NO SPEC, NO CLAIM. Without declared operations there is nothing to point a test at,
// and announcing a gap anyway is the same overclaim pointed the other way.
func TestNoSpecMeansNoDisclosure(t *testing.T) {
	h := NewHandler()
	for name, findings := range map[string][]types.Finding{
		"no findings at all": nil,
		"findings but no spec": {
			{RuleID: "nuclei::something", Severity: types.SeverityHigh},
		},
		"spec with zero operations": {specFinding("0")},
		"spec with an unreadable count": {
			{RuleID: specFoundRule, ToolArgs: map[string]string{"operations": "lots"}},
		},
	} {
		if got := h.CoverageGaps(types.Asset{Type: types.AssetAPI}, findings); len(got) != 0 {
			t.Errorf("%s: declared %d gap(s); nothing is testable so nothing should be claimed", name, len(got))
		}
	}
}

// A spec that declares zero operations and a scan that never found a spec are DIFFERENT
// facts. Only the first means the target genuinely has nothing to test, and collapsing
// them would hide a failed ingest behind "nothing to see here".
func TestZeroOperationsIsDistinguishedFromNoSpec(t *testing.T) {
	if n, ok := declaredOperations([]types.Finding{specFinding("0")}); !ok || n != 0 {
		t.Errorf("a spec declaring zero operations must report ok=true, n=0; got ok=%v n=%d", ok, n)
	}
	if _, ok := declaredOperations(nil); ok {
		t.Error("no spec must report ok=false, not a zero count")
	}
}

// The handler must actually satisfy the optional interface, or the orchestrator never
// calls it and every assertion above is about a method nothing invokes.
func TestHandlerImplementsCoverageReporter(t *testing.T) {
	var _ asset.CoverageReporter = NewHandler()
}
