package hooks

import (
	"testing"

	"github.com/ClatTribe/tsengine/pkg/types"
)

// Making the cloud agent's verification tier follow the ADR-0024 rung had a second-order effect that
// had to be handled rather than discovered later: an unchecked path stopped reaching the "verified"
// 0.95 floor and, with no entry in toolBaseConfidence, fell to the 0.50 UNKNOWN-TOOL default —
// beneath semgrep. That would have traded an overclaim for an underclaim on a producer whose
// grounding we can actually describe.
//
// What this pins is the SHAPE, not the constants: a graph-only path must sit meaningfully above the
// unknown-tool default and meaningfully below a provider-confirmed one, so the ladder is visible in
// confidence and not only in the verification string.
func TestConfidence_CloudAgentRungsAreSeparated(t *testing.T) {
	run := func(f types.Finding) float64 {
		out, _ := NewConfidence().Finalize([]types.Finding{f})
		return out[0].Confidence
	}

	graphOnly := run(types.Finding{Tool: "cloudagent", VerificationStatus: types.VerificationPatternMatch})
	confirmed := run(types.Finding{Tool: "cloudagent", VerificationStatus: types.VerificationVerified})
	unknownTool := run(types.Finding{Tool: "some-tool-we-never-heard-of", VerificationStatus: types.VerificationPatternMatch})

	if graphOnly <= unknownTool {
		t.Errorf("graph-only cloud path = %.2f, no better than an unknown tool (%.2f) — validatePath "+
			"refuses ungrounded edges, and that is worth something", graphOnly, unknownTool)
	}
	if graphOnly >= confirmed {
		t.Errorf("graph-only %.2f is not below provider-confirmed %.2f — asking the provider has to "+
			"buy something, or the rung is decorative", graphOnly, confirmed)
	}
	if confirmed < 0.95 {
		t.Errorf("provider-confirmed = %.2f, below the 0.95 actively-confirmed floor", confirmed)
	}
}
