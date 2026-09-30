package uicheck

import (
	"strings"
	"testing"
)

// Environment gated the pentester and moved nothing else because NOTHING could set it: the backend
// accepted it and no page offered it, so every asset read "treated as production" forever. The
// control must exist, must show the server's label (an unset asset says it is treated as production
// rather than rendering blank), and must never apply a name-based guess on its own.
func TestAssetsPageLetsAHumanDeclareTheEnvironment(t *testing.T) {
	page := stripComments(frontendFile(t, "app", "(app)", "assets", "page.tsx"))
	if !strings.Contains(page, "<EnvironmentSelect") {
		t.Error("the assets page offers no way to declare an asset's environment")
	}
	c := stripComments(frontendFile(t, "components", "assets", "environment-select.tsx"))
	for _, want := range []struct{ s, why string }{
		{"setAssetEnvironment(", "the control does not reach the server"},
		{"treated as production", "an unset asset renders as blank instead of saying it is gated as production"},
		{"confirm?", "a name-based suggestion is not presented as something a human confirms"},
	} {
		if !strings.Contains(c, want.s) {
			t.Errorf("environment control: %s (missing %q)", want.why, want.s)
		}
	}
	if strings.Contains(c, "useEffect") {
		t.Error("the environment control must not apply anything on render — a suggestion is confirmed by a click, never applied")
	}
}
