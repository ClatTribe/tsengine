package operate

import (
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/pkg/types"
)

func vulnerableWorkspace() Workspace {
	return Workspace{
		Provider: "gworkspace", Org: "acme.example",
		Users: []User{
			{Email: "ceo@acme.example", SuperAdmin: true, MFA: false},  // admin w/o MFA → critical
			{Email: "it@acme.example", Admin: true, MFA: true},         // fine
			{Email: "sales@acme.example", MFA: false},                  // user w/o MFA → medium
			{Email: "old@acme.example", MFA: true, LastLoginDays: 200}, // stale → low
			{Email: "gone@acme.example", Admin: true, Suspended: true}, // suspended → ignored
		},
		Domains: []DomainConfig{
			{Name: "acme.example", DMARC: "none", SPF: true, DKIM: false}, // DMARC not enforced + DKIM missing
		},
		OAuthGrants: []OAuthGrant{
			{App: "SketchyCRM", Scopes: []string{"https://www.googleapis.com/auth/admin.directory.user"}, Users: 50, AdminScope: true}, // critical
		},
	}
}

func hardenedWorkspace() Workspace {
	return Workspace{
		Provider: "gworkspace", Org: "secure.example",
		Users: []User{
			{Email: "ceo@secure.example", SuperAdmin: true, MFA: true},
			{Email: "it@secure.example", Admin: true, MFA: true},
			{Email: "sales@secure.example", MFA: true, LastLoginDays: 2},
		},
		Domains: []DomainConfig{{Name: "secure.example", DMARC: "reject", SPF: true, DKIM: true}},
		OAuthGrants: []OAuthGrant{
			{App: "SanctionedTool", Scopes: []string{"openid", "email"}, Users: 3, Verified: true},
		},
	}
}

func ruleSet(fs []types.Finding) map[string]types.Finding {
	m := map[string]types.Finding{}
	for _, f := range fs {
		m[f.RuleID] = f
	}
	return m
}

func TestAssess_VulnerableWorkspaceGrounded(t *testing.T) {
	fs := Assess(vulnerableWorkspace(), Options{})
	rules := ruleSet(fs)

	// the critical findings must fire AND cite the exact offending entity
	if f, ok := rules["operate::admin-without-mfa"]; !ok {
		t.Error("missing admin-without-mfa")
	} else if f.Severity != types.SeverityCritical || f.Endpoint != "ceo@acme.example" {
		t.Errorf("admin-without-mfa not grounded to the admin: %+v", f)
	}
	if f, ok := rules["operate::oauth-admin-scope"]; !ok {
		t.Error("missing oauth-admin-scope")
	} else if f.Severity != types.SeverityCritical || f.Endpoint != "SketchyCRM" {
		t.Errorf("oauth-admin-scope not grounded to the app: %+v", f)
	}
	if f, ok := rules["operate::dmarc-not-enforced"]; !ok || f.Endpoint != "acme.example" {
		t.Errorf("dmarc finding missing/ungrounded: %+v", f)
	}
	for _, want := range []string{"operate::user-without-mfa", "operate::stale-account", "operate::spf-dkim-missing"} {
		if _, ok := rules[want]; !ok {
			t.Errorf("missing expected finding %s", want)
		}
	}

	// every finding must carry a compliance mapping (so it flows into GRC) + cite an entity
	for _, f := range fs {
		if f.Compliance == nil {
			t.Errorf("finding %s has no compliance mapping", f.RuleID)
		}
		if f.Endpoint == "" {
			t.Errorf("finding %s is ungrounded (no cited entity)", f.RuleID)
		}
		if f.Tool != "operate" || f.VerificationStatus != types.VerificationVerified {
			t.Errorf("finding %s metadata wrong: %+v", f.RuleID, f)
		}
	}

	// the suspended admin must NOT produce findings (grounding excludes inactive)
	for _, f := range fs {
		if strings.Contains(f.Endpoint, "gone@") {
			t.Errorf("suspended account should not be flagged: %+v", f)
		}
	}
}

func TestAssess_HardenedWorkspaceClean(t *testing.T) {
	fs := Assess(hardenedWorkspace(), Options{})
	if len(fs) != 0 {
		t.Fatalf("a hardened workspace must yield ZERO findings (grounding isn't noise); got %d: %+v", len(fs), fs)
	}
}

func TestAssess_StaleAdminIsHigherSeverity(t *testing.T) {
	ws := Workspace{Users: []User{
		{Email: "admin@x", Admin: true, MFA: true, LastLoginDays: 365},
		{Email: "user@x", MFA: true, LastLoginDays: 365},
	}}
	rules := map[string]types.Finding{}
	for _, f := range Assess(ws, Options{}) {
		if f.RuleID == "operate::stale-account" {
			rules[f.Endpoint] = f
		}
	}
	if rules["admin@x"].Severity != types.SeverityHigh {
		t.Errorf("a stale ADMIN should be high, got %s", rules["admin@x"].Severity)
	}
	if rules["user@x"].Severity != types.SeverityLow {
		t.Errorf("a stale user should be low, got %s", rules["user@x"].Severity)
	}
}

func TestAssess_SuperAdminThreshold(t *testing.T) {
	ws := Workspace{Org: "o"}
	for i := 0; i < 5; i++ {
		ws.Users = append(ws.Users, User{Email: "sa", SuperAdmin: true, MFA: true})
	}
	var got bool
	for _, f := range Assess(ws, Options{MaxSuperAdmins: 3}) {
		if f.RuleID == "operate::excess-super-admins" {
			got = true
		}
	}
	if !got {
		t.Error("5 super-admins with max=3 should flag excess-super-admins")
	}
}
