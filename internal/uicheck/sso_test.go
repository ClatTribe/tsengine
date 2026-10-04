package uicheck

import (
	"strings"
	"testing"
)

// Single sign-on's reader half. Every way back from the identity provider must land on a page that
// says what happened; the second-factor path must keep its challenge in the httpOnly cookie; and the
// owner's panel must show the redirect URI (the step people get wrong) and never touch the secret.
func TestSSOPagesExplainEveryOutcome(t *testing.T) {
	cb := stripComments(frontendFile(t, "app", "api", "sso", "callback", "route.ts"))
	for _, want := range []struct{ s, why string }{
		{"sso_error=", "a failed sign-in must come back to the login page with the reason"},
		{`back("step=code")`, "a sign-in that still owes the person's own code must go to the code step"},
		{"MFA_COOKIE", "the second-factor challenge must ride in the httpOnly cookie"},
		{"error_description", "the provider's own refusal must be shown, not swallowed"},
	} {
		if !strings.Contains(cb, want.s) {
			t.Errorf("sso callback route: %s (missing %q)", want.why, want.s)
		}
	}
	if strings.Contains(cb, "challenge=") {
		t.Error("the sso callback puts the second-factor challenge in a URL")
	}
	login := stripComments(frontendFile(t, "app", "login", "page.tsx"))
	for _, want := range []string{`q.get("step") === "code"`, `q.get("sso_error")`, "/api/sso/start", "window.location.assign(b.authorize_url)"} {
		if !strings.Contains(login, want) {
			t.Errorf("login page: missing %q", want)
		}
	}
	session := stripComments(frontendFile(t, "app", "api", "session", "route.ts"))
	if !strings.Contains(session, `"sso_required"`) {
		t.Error("the session route must say a workspace signs in through SSO, not report a generic failure")
	}
	ctl := stripComments(frontendFile(t, "components", "settings", "sso-control.tsx"))
	if !strings.Contains(ctl, "sso.redirect_uri") {
		t.Error("the SSO panel must show the redirect URI to register at the provider")
	}
	if strings.Contains(ctl, "client_secret_ref") {
		t.Error("the SSO panel reads the stored secret reference")
	}
	if !strings.Contains(ctl, "except the owner") {
		t.Error("the enforcement option must say the owner's password is kept as the break-glass")
	}
}
