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

// The operator side: the login form asks for the code, the challenge never leaves an httpOnly cookie,
// and — the bug this guards — an operator refused for want of two-factor is shown enrolment rather than
// redirected to the login page, which would see a valid session and send them straight back.
func TestOperatorConsoleEnrolsRatherThanLoops(t *testing.T) {
	page := stripComments(frontendFile(t, "app", "operator", "page.tsx"))
	for _, want := range []struct{ s, why string }{
		{"if (result.setupRequired) {", "the console must branch on the server's two_factor_setup_required, not treat it as signed-out"},
		{"canDisable={false}", "under the deployment policy the control must not offer turning two-factor off"},
		{"enabled={!!me.two_factor_enabled}", "the account-security panel must render the server's state"},
	} {
		if !strings.Contains(page, want.s) {
			t.Errorf("operator console: %s (missing %q)", want.why, want.s)
		}
	}
	// Order matters: the enrolment branch must be taken BEFORE the no-queue redirect, or a refused queue
	// still redirects and the loop is back.
	if i, j := strings.Index(page, "if (result.setupRequired) {"), strings.Index(page, `if (!queue) redirect("/operator/login")`); i < 0 || j < 0 || i > j {
		t.Error("operator console: the two-factor enrolment branch must come before the no-queue redirect to the login page")
	}
	lib := stripComments(frontendFile(t, "lib", "operator.ts"))
	if !strings.Contains(lib, `"two_factor_setup_required"`) {
		t.Error("lib/operator.ts must recognise the setup-required refusal, or the console loops through the login page")
	}
	form := stripComments(frontendFile(t, "components", "operator", "login-form.tsx"))
	if !strings.Contains(form, "state?.needCode") || !strings.Contains(form, `name="code"`) {
		t.Error("the operator login form must ask for the code when the server says one is owed")
	}
	actions := stripComments(frontendFile(t, "app", "operator", "actions.ts"))
	if !strings.Contains(actions, "OP_MFA_COOKIE") || strings.Contains(actions, "return { needCode: true, challenge") {
		t.Error("the operator challenge must live in its httpOnly cookie and never be returned to the browser")
	}
}
