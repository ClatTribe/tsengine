package uicheck

import (
	"strings"
	"testing"
)

// The AI value card renders the server's refusals as given: cost per proof only when the server computed
// it (never derived client-side, which would divide a partial cost by the whole outcome), unpriced runs
// named rather than read as free, fixes proven closed shown as context and not credited, and the paths not
// yet metered named. FAILS rather than skips when the file moves (§14.2 rule 6).
func TestAIValueCardRendersTheServersRefusals(t *testing.T) {
	src := stripComments(frontendFile(t, "components", "engineer", "ai-value.tsx"))
	if strings.Contains(src, "s.usd / s.verified") || strings.Contains(src, "usd / ") {
		t.Error("the card computes cost per proof itself; it must render the server's cost_per_verified")
	}
	for _, f := range []string{"s.cost_per_verified !== undefined", "s.unknown_cost_runs", "v.fixes_proven_closed", "v.unmetered"} {
		if !strings.Contains(src, f) {
			t.Errorf("the AI value card never renders %s", f)
		}
	}
	if !strings.Contains(src, "not credited to the AI") {
		t.Error("fixes proven closed must be stated as context, not credited to the AI")
	}
}
