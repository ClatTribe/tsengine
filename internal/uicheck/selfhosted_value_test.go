package uicheck

import (
	"strings"
	"testing"
)

// Self-hosted runs are recorded at $0 with the cost known. Rendered as a bare $0 they read as a missing
// number; the value view says what they are. FAILS rather than skips when the file moves (§14.2 rule 6).
func TestAIValueSaysSelfHostedRunsAreFree(t *testing.T) {
	src := stripComments(frontendFile(t, "components", "engineer", "ai-value.tsx"))
	for _, must := range []string{"s.self_hosted", "self-hosted model ($0)", "count as $0 toward your monthly AI budget"} {
		if !strings.Contains(src, must) {
			t.Errorf("the AI value view no longer renders %q", must)
		}
	}
}
