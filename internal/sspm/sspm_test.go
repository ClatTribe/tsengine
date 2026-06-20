package sspm

import (
	"strings"
	"testing"
	"time"

	"github.com/ClatTribe/tsengine/pkg/types"
)

func ruleSet(fs []types.Finding) map[string]types.Finding {
	m := map[string]types.Finding{}
	for _, f := range fs {
		m[f.RuleID] = f
	}
	return m
}

// A securely-configured org must yield ZERO findings — the determinism /
// testability invariant (a hardened target is clean), same as operate.
func TestAssessGitHubOrg_HardenedIsClean(t *testing.T) {
	org := GitHubOrg{
		Login:                       "acme",
		TwoFactorRequired:           true,
		DefaultRepoPermission:       "read",
		MembersCanCreatePublicRepos: false,
		SecretScanningEnabled:       true,
		Members: []OrgMember{
			{Login: "founder", Role: "admin", TwoFactor: true},
			{Login: "dev1", Role: "member", TwoFactor: true},
		},
		Apps:     []OrgApp{{Name: "CI", Verified: true, AdminPermission: false}},
		Webhooks: []OrgWebhook{{URL: "https://ci.acme.io/hook", SSLVerify: true, Active: true}},
	}
	if f := AssessGitHubOrg(org, Options{Now: time.Unix(0, 0)}); len(f) != 0 {
		t.Errorf("hardened org must be clean, got %d findings: %+v", len(f), f)
	}
}

// A weak org must produce the expected grounded findings, each citing its setting.
func TestAssessGitHubOrg_WeakOrgFindings(t *testing.T) {
	org := GitHubOrg{
		Login:                       "acme",
		TwoFactorRequired:           false,
		DefaultRepoPermission:       "write",
		MembersCanCreatePublicRepos: true,
		SecretScanningEnabled:       false,
		Members: []OrgMember{
			{Login: "founder", Role: "admin", TwoFactor: false},
			{Login: "o2", Role: "admin", TwoFactor: true},
			{Login: "o3", Role: "admin", TwoFactor: true},
			{Login: "o4", Role: "admin", TwoFactor: true}, // 4 owners > default 3 → sprawl
			{Login: "dev1", Role: "member", TwoFactor: false},
		},
		OutsideCollaborators: []OrgMember{{Login: "contractor", Role: "member"}},
		Apps: []OrgApp{
			{Name: "ShadyBot", Verified: false, AdminPermission: true},
			{Name: "Unverified", Verified: false, AdminPermission: false},
		},
		Webhooks: []OrgWebhook{{URL: "http://attacker.test/hook", SSLVerify: false, Active: true}},
	}
	got := ruleSet(AssessGitHubOrg(org, Options{Now: time.Unix(0, 0)}))

	for _, want := range []string{
		"sspm::github::2fa-not-enforced",
		"sspm::github::member-without-2fa", // founder (admin) + dev1 → present
		"sspm::github::broad-default-repo-permission",
		"sspm::github::members-can-create-public-repos",
		"sspm::github::secret-scanning-disabled",
		"sspm::github::outside-collaborators",
		"sspm::github::owner-sprawl",
		"sspm::github::app-admin-scope",
		"sspm::github::app-unverified",
		"sspm::github::webhook-no-ssl-verify",
	} {
		if _, ok := got[want]; !ok {
			t.Errorf("missing expected finding %q", want)
		}
	}

	// Grounding spot-checks: findings cite the offending entity + carry compliance.
	if f := got["sspm::github::2fa-not-enforced"]; f.Tool != "sspm" || f.Severity != "high" ||
		f.Compliance == nil || len(f.Compliance.SOC2) == 0 || f.VerificationStatus != types.VerificationVerified {
		t.Errorf("2fa finding not grounded/compliance-mapped: %+v", f)
	}
	if f := got["sspm::github::app-admin-scope"]; !strings.Contains(f.Endpoint, "ShadyBot") {
		t.Errorf("app-admin finding should cite the app: %+v", f)
	}
}

// An org owner without 2FA is rated higher than a regular member.
func TestMember2FA_OwnerIsHigher(t *testing.T) {
	org := GitHubOrg{Login: "x", Members: []OrgMember{
		{Login: "owner", Role: "admin", TwoFactor: false},
		{Login: "member", Role: "member", TwoFactor: false},
	}}
	sevByLogin := map[string]types.Severity{}
	for _, f := range AssessGitHubOrg(org, Options{Now: time.Unix(0, 0)}) {
		if f.RuleID == "sspm::github::member-without-2fa" {
			sevByLogin[f.Endpoint] = f.Severity
		}
	}
	if sevByLogin["github:x/owner"] != types.SeverityHigh || sevByLogin["github:x/member"] != types.SeverityMedium {
		t.Errorf("owner should be high, member medium: %+v", sevByLogin)
	}
}
