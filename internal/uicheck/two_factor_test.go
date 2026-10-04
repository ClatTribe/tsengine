package uicheck

import (
	"strings"
	"testing"
)

// Two-factor sign-in has a login half and a settings half, and each is a place where the page could
// quietly undo what the server enforces. FAILS rather than skips when a file moves.

// The login page must STOP at the password when the server says a code is owed. Navigating on any 2xx
// would land a person on a dashboard that 401s everything — reading as a broken product rather than as
// "enter your code" — and the session route must hold the challenge in an httpOnly cookie, not hand it
// to script.
func TestLoginAsksForTheSecondFactor(t *testing.T) {
	login := stripComments(frontendFile(t, "app", "login", "page.tsx"))
	for _, want := range []struct{ s, why string }{
		{"b.two_factor_required", "the login page must check whether the server asked for a code before navigating"},
		{"/api/session/verify", "the code step must post to the verify route"},
		{"recovery_code", "a person who lost their phone must be able to use a recovery code"},
		{"b.expired", "an expired or burned sign-in must send the person back to the password step"},
	} {
		if !strings.Contains(login, want.s) {
			t.Errorf("login page: %s (missing %q)", want.why, want.s)
		}
	}
	route := stripComments(frontendFile(t, "app", "api", "session", "route.ts"))
	if !strings.Contains(route, "MFA_COOKIE") || strings.Contains(route, "challenge: data.challenge") {
		t.Error("the session route must keep the second-factor challenge in an httpOnly cookie and never return it to the browser")
	}
}

// The settings control must render the server's state, never infer it, and must ask for BOTH factors
// before weakening the protection — matching the server, so a click is not refused for a reason the
// form never asked about.
func TestTwoFactorControlRendersServerStateAndAsksForBothFactors(t *testing.T) {
	ctl := stripComments(frontendFile(t, "components", "settings", "two-factor-control.tsx"))
	for _, want := range []struct{ s, why string }{
		{"enabled ?", "the on/off state must come from the enabled prop (the server's two_factor_enabled)"},
		{"remaining", "the recovery codes left must be shown — running out is only discovered on the day the phone is lost"},
		{"will not be shown again", "recovery codes must be presented as shown once"},
		{"not on until that code is", "enrolment must say it is not on until a code is accepted"},
		{"!password || !code.trim()", "turning off / replacing codes must require the password AND a code, as the server does"},
	} {
		if !strings.Contains(ctl, want.s) {
			t.Errorf("two-factor control: %s (missing %q)", want.why, want.s)
		}
	}
	page := stripComments(frontendFile(t, "app", "(app)", "settings", "page.tsx"))
	if !strings.Contains(page, "enabled={!!me?.two_factor_enabled}") {
		t.Error("settings must pass the server's two_factor_enabled to the control")
	}
}
