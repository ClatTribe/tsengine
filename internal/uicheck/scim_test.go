package uicheck

import (
	"strings"
	"testing"
)

// The SCIM panel. The token is returned once and only its digest is kept, so the page must say so at the
// moment it shows it — an owner who closes the tab believing they can come back for it is left with a
// provider that cannot authenticate and no way to recover the value. And the panel must offer no owner
// role: provisioning never creates one, and offering it would invite exactly the request the server
// refuses. FAILS rather than skips when the file moves (§14.2 rule 6).
func TestSCIMControlSaysTheTokenIsShownOnce(t *testing.T) {
	src := stripComments(frontendFile(t, "components", "settings", "scim-control.tsx"))
	if !strings.Contains(src, "shown once") {
		t.Error("the SCIM panel shows the token without saying it is shown once and cannot be retrieved")
	}
	if !strings.Contains(src, "{token && (") {
		t.Error("the minted token must be rendered from the mint response (it is never retrievable later)")
	}
	if strings.Contains(src, `value="owner"`) {
		t.Error("the SCIM panel offers owner as a provisioning role; provisioning never creates owners")
	}
	for _, f := range []string{"s.provisioned", "s.deactivated", "s.base_url"} {
		if !strings.Contains(src, f) {
			t.Errorf("the SCIM panel never renders %s", f)
		}
	}
}
