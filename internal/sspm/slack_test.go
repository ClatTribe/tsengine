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
		TwoFactorRequired:     sb(true),
		SSOEnforced:           sb(true),
		ApprovedAppsOnly:      sb(true),
		PublicLinkSharing:     false,
		InviteDomainAllowlist: sb(true),
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
		TwoFactorRequired:     sb(false),
		SSOEnforced:           sb(false),
		ApprovedAppsOnly:      sb(false),
		PublicLinkSharing:     true,
		InviteDomainAllowlist: sb(false),
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
		Name: "x", SSOEnforced: sb(true), ApprovedAppsOnly: sb(true), InviteDomainAllowlist: sb(true),
		Members: []SlackMember{{Name: "u", Role: "member", TwoFactor: false}},
	}
	for _, f := range AssessSlack(ws, Options{Now: time.Unix(0, 0)}) {
		if strings.Contains(f.RuleID, "2fa") {
			t.Errorf("SSO-enforced workspace should not raise a 2FA finding: %s", f.RuleID)
		}
	}
}

// ── ABSENT IS NOT MISCONFIGURED ──────────────────────────────────────────────────────────────────

// A snapshot that carries only a workspace name used to produce four findings — 2FA not enforced,
// SSO not enforced, app approval disabled, no invite allowlist — about settings it never mentioned.
// The package promises a hardened app yields zero findings; the converse, an app we know nothing
// about yielding four, is the same claim made backwards.
//
// It reaches further than the screen: these carry SOC 2 / PCI / CIS mappings into an auditor's
// evidence pack, so an incomplete export manufactured evidence of control failures nobody observed.
func TestUnreportedSlackSettings_AreNotFindings(t *testing.T) {
	got := AssessSlack(SlackWorkspace{Name: "acme"}, Options{Now: time.Unix(0, 0)})
	if len(got) != 0 {
		t.Fatalf("a workspace that reported only its name produced %d finding(s) about settings it "+
			"never mentioned: %+v", len(got), got)
	}
}

// The other half: a setting really recorded as off is still a finding. The fix must not buy silence
// by going blind.
func TestExplicitlyOffSlackSettings_AreStillFindings(t *testing.T) {
	got := AssessSlack(SlackWorkspace{
		Name: "acme", TwoFactorRequired: sb(false), SSOEnforced: sb(false),
	}, Options{Now: time.Unix(0, 0)})
	var found bool
	for _, f := range got {
		if f.RuleID == "sspm::slack::2fa-not-enforced" {
			found = true
		}
	}
	if !found {
		t.Errorf("2FA and SSO both recorded as off produced no finding: %+v", got)
	}
}

// A member's own reported lack of 2FA is grounded in the MEMBER's record. An unreported ORG setting
// must not silently drop it — the org setting suppresses that finding only when it proves enforcement.
func TestMemberWithout2FA_SurvivesAnUnreportedOrgSetting(t *testing.T) {
	got := AssessSlack(SlackWorkspace{
		Name: "acme", Members: []SlackMember{{Name: "dev", Role: "member", TwoFactor: false}},
	}, Options{Now: time.Unix(0, 0)})
	var found bool
	for _, f := range got {
		if f.RuleID == "sspm::slack::member-without-2fa" {
			found = true
		}
	}
	if !found {
		t.Errorf("a member who reported no 2FA was dropped because the workspace setting was "+
			"unreported: %+v", got)
	}
}
