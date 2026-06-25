package sspm

import (
	"strings"
	"testing"
	"time"

	"github.com/ClatTribe/tsengine/pkg/types"
)

// A securely-configured Slack workspace must yield ZERO findings.
func TestAssessSlack_HardenedIsClean(t *testing.T) {
	ws := SlackWorkspace{
		Name:                  "acme",
		TwoFactorRequired:     true,
		SSOEnforced:           true,
		ApprovedAppsOnly:      true,
		PublicLinkSharing:     false,
		InviteDomainAllowlist: true,
		Members: []SlackMember{
			{Name: "founder", Role: "owner", TwoFactor: true},
			{Name: "dev1", Role: "member", TwoFactor: true},
		},
		Apps: []SlackApp{{Name: "GoogleCal", Verified: true, BroadScope: false}},
	}
	if f := AssessSlack(ws, Options{Now: time.Unix(0, 0)}); len(f) != 0 {
		t.Errorf("hardened Slack workspace must be clean, got %d: %+v", len(f), f)
	}
}

// A weak workspace produces the expected grounded findings.
func TestAssessSlack_WeakWorkspace(t *testing.T) {
	ws := SlackWorkspace{
		Name:                  "acme",
		TwoFactorRequired:     false,
		SSOEnforced:           false,
		ApprovedAppsOnly:      false,
		PublicLinkSharing:     true,
		InviteDomainAllowlist: false,
		Members: []SlackMember{
			{Name: "founder", Role: "owner", TwoFactor: false},
			{Name: "a2", Role: "admin", TwoFactor: true},
			{Name: "a3", Role: "admin", TwoFactor: true},
			{Name: "a4", Role: "admin", TwoFactor: true}, // 4 owners/admins > 3 → sprawl
			{Name: "dev1", Role: "member", TwoFactor: false},
			{Name: "ext", Role: "guest", TwoFactor: false}, // guest: not a 2FA finding
		},
		Apps: []SlackApp{
			{Name: "DataBot", Verified: false, BroadScope: true},
			{Name: "Unverified", Verified: false, BroadScope: false},
		},
	}
	got := map[string]types.Finding{}
	for _, f := range AssessSlack(ws, Options{Now: time.Unix(0, 0)}) {
		got[f.RuleID] = f
	}
	for _, want := range []string{
		"sspm::slack::2fa-not-enforced",
		"sspm::slack::member-without-2fa",
		"sspm::slack::sso-not-enforced",
		"sspm::slack::app-approval-disabled",
		"sspm::slack::app-broad-scope",
		"sspm::slack::app-unverified",
		"sspm::slack::public-link-sharing",
		"sspm::slack::guest-accounts",
		"sspm::slack::admin-sprawl",
		"sspm::slack::no-invite-domain-allowlist",
	} {
		if _, ok := got[want]; !ok {
			t.Errorf("missing expected finding %q", want)
		}
	}
	// Guest must NOT generate a member-without-2fa finding (only real members do).
	for _, f := range got {
		if f.RuleID == "sspm::slack::member-without-2fa" && strings.Contains(f.Endpoint, "/ext") {
			t.Error("a guest should not be flagged for member 2FA")
		}
	}
	// Grounding spot-check.
	if f := got["sspm::slack::app-broad-scope"]; f.Tool != "sspm" || f.Severity != "high" ||
		f.Compliance == nil || !strings.Contains(f.Endpoint, "DataBot") {
		t.Errorf("broad-scope app finding not grounded: %+v", f)
	}
}

// SSO enforcement is treated as carrying MFA upstream → no 2FA findings.
func TestAssessSlack_SSOSuppresses2FA(t *testing.T) {
	ws := SlackWorkspace{
		Name: "x", SSOEnforced: true, ApprovedAppsOnly: true, InviteDomainAllowlist: true,
		Members: []SlackMember{{Name: "u", Role: "member", TwoFactor: false}},
	}
	for _, f := range AssessSlack(ws, Options{Now: time.Unix(0, 0)}) {
		if strings.Contains(f.RuleID, "2fa") {
			t.Errorf("SSO-enforced workspace should not raise a 2FA finding: %s", f.RuleID)
		}
	}
}
