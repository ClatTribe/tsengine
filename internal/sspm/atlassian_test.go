package sspm

import (
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/pkg/types"
)

func hardenedAtlassian() AtlassianOrg {
	return AtlassianOrg{
		Name:              "acme",
		TwoFactorRequired: true,
		SSOEnforced:       true,
		PublicSignup:      false,
		ApprovedAppsOnly:  true,
		Members: []AtlassianMember{
			{Email: "admin@acme.com", Role: "admin", TwoFactor: true, APIToken: false},
			{Email: "dev@acme.com", Role: "member", TwoFactor: true, APIToken: false},
		},
		Apps:   []AtlassianApp{{Name: "Tempo", Verified: true, BroadScope: false}},
		Spaces: []ConfluenceSpace{{Key: "ENG", PublicAccess: false}},
	}
}

func TestAssessAtlassian_HardenedYieldsZero(t *testing.T) {
	if f := AssessAtlassian(hardenedAtlassian(), Options{}); len(f) != 0 {
		t.Fatalf("a hardened Atlassian org must yield zero findings, got %d: %+v", len(f), f)
	}
}

func TestAssessAtlassian_FlagsMisconfig(t *testing.T) {
	org := AtlassianOrg{
		Name:              "acme",
		TwoFactorRequired: false,
		SSOEnforced:       false,
		PublicSignup:      true,
		ApprovedAppsOnly:  false,
		Members: []AtlassianMember{
			{Email: "admin@acme.com", Role: "admin", TwoFactor: false, APIToken: true},
			{Email: "dev@acme.com", Role: "member", TwoFactor: true, APIToken: false},
		},
		Apps:   []AtlassianApp{{Name: "ShadyAddon", Verified: false, BroadScope: true}},
		Spaces: []ConfluenceSpace{{Key: "PUB", PublicAccess: true}},
	}
	f := AssessAtlassian(org, Options{})
	rules := map[string]types.Severity{}
	for _, x := range f {
		rules[x.RuleID] = x.Severity
		if x.Tool != "sspm" || x.VerificationStatus != types.VerificationVerified {
			t.Errorf("finding not grounded-verified: %+v", x)
		}
		if !strings.HasPrefix(x.Endpoint, "atlassian:acme") {
			t.Errorf("endpoint not grounded to the org: %q", x.Endpoint)
		}
	}
	for _, want := range []string{
		"sspm::atlassian::2fa-not-enforced",
		"sspm::atlassian::sso-not-enforced",
		"sspm::atlassian::public-signup",
		"sspm::atlassian::confluence-public-space",
		"sspm::atlassian::user-api-token",
		"sspm::atlassian::app-approval-disabled",
		"sspm::atlassian::app-broad-scope",
		"sspm::atlassian::member-without-2fa",
	} {
		if _, ok := rules[want]; !ok {
			t.Errorf("expected finding %q not emitted", want)
		}
	}
	// public Confluence space is a high-severity data-exposure finding
	if rules["sspm::atlassian::confluence-public-space"] != types.SeverityHigh {
		t.Errorf("confluence-public-space should be high, got %q", rules["sspm::atlassian::confluence-public-space"])
	}
	// the admin without 2FA must be high
	if rules["sspm::atlassian::member-without-2fa"] != types.SeverityHigh {
		t.Errorf("admin member-without-2fa should be high, got %q", rules["sspm::atlassian::member-without-2fa"])
	}
}

func TestAssessAtlassian_APITokenFlaggedEvenWhenSSOOn(t *testing.T) {
	org := hardenedAtlassian() // SSO on, but a user keeps a long-lived API token (SSO bypass)
	org.Members[1].APIToken = true
	f := AssessAtlassian(org, Options{})
	if len(f) != 1 || f[0].RuleID != "sspm::atlassian::user-api-token" {
		t.Fatalf("an API token must be flagged even with SSO enforced, got %+v", f)
	}
}
