package shadowit

import (
	"testing"

	"github.com/ClatTribe/tsengine/pkg/types"
)

func grants() []Grant {
	return []Grant{
		// "Loom" — two employees connected it, no admin consent, a sensitive scope → shadow IT + sensitive.
		{User: "ana", App: "Loom", Scopes: []string{"profile", "drive.readonly"}},
		{User: "bob", App: "Loom", Scopes: []string{"profile"}},
		// "Okta" — admin-consented, verified, narrow → sanctioned (no finding).
		{User: "ana", App: "Okta", Scopes: []string{"openid"}, AdminConsent: true, Verified: true},
		// "RandTool" — admin-consented + verified BUT a sensitive scope → sensitive-unverified? no, verified.
		{User: "cara", App: "Mailtool", Scopes: []string{"mail.read"}, AdminConsent: true, Verified: false}, // sensitive + unverified
	}
}

func TestInventory_Aggregates(t *testing.T) {
	inv := Inventory(grants())
	by := map[string]App{}
	for _, a := range inv {
		by[a.Name] = a
	}
	loom := by["Loom"]
	if len(loom.Users) != 2 {
		t.Errorf("Loom should aggregate 2 users, got %v", loom.Users)
	}
	if !loom.ShadowIT {
		t.Error("Loom has no admin consent → shadow IT")
	}
	if !loom.Sensitive {
		t.Error("Loom holds drive.readonly → sensitive")
	}
	if by["Okta"].ShadowIT {
		t.Error("Okta is admin-consented → NOT shadow IT (sanctioned)")
	}
}

func TestFindings_RiskClassification(t *testing.T) {
	f := Findings(Inventory(grants()))
	rules := map[string]types.Severity{}
	for _, x := range f {
		rules[x.RuleID] = x.Severity
	}
	// Loom: shadow IT + sensitive → high.
	if rules["shadowit::unsanctioned-sensitive"] != types.SeverityHigh {
		t.Errorf("shadow-IT app with sensitive scope should be high, got %v", rules["shadowit::unsanctioned-sensitive"])
	}
	// Mailtool: admin-consented (not shadow IT) but sensitive + unverified → medium.
	if rules["shadowit::sensitive-unverified"] != types.SeverityMedium {
		t.Errorf("sensitive+unverified sanctioned app should be medium, got %v", rules["shadowit::sensitive-unverified"])
	}
	// Okta (sanctioned, verified, narrow) must produce NO finding.
	for _, x := range f {
		if x.Endpoint == "saas-app:Okta" {
			t.Error("a sanctioned, verified, narrow-scope app must not be flagged (FP guard)")
		}
	}
}

func TestFindings_ShadowITWithoutSensitiveIsMedium(t *testing.T) {
	// An employee-connected app with only a benign scope → shadow IT (medium), not high.
	f := Findings(Inventory([]Grant{{User: "x", App: "Trello", Scopes: []string{"read:boards"}}}))
	if len(f) != 1 || f[0].RuleID != "shadowit::unsanctioned" || f[0].Severity != types.SeverityMedium {
		t.Errorf("benign shadow-IT app should be a medium unsanctioned finding, got %+v", f)
	}
}

func TestFindings_GroundedNoSignalNoFinding(t *testing.T) {
	// A fully sanctioned, verified, narrow app → nothing (grounded).
	f := Findings(Inventory([]Grant{{User: "x", App: "SSO", Scopes: []string{"openid"}, AdminConsent: true, Verified: true}}))
	if len(f) != 0 {
		t.Errorf("a clean sanctioned app must produce no finding, got %+v", f)
	}
}

func TestIsSensitive_Taxonomy(t *testing.T) {
	// FN expansion: these high-risk scopes must now classify as sensitive.
	sensitive := []string{
		"https://www.googleapis.com/auth/cloud-platform", // GCP god-mode
		"https://www.googleapis.com/auth/bigquery",
		"Application.ReadWrite.All", // M365 app-secret minting
		"User.ReadWrite.All",
		"Sites.FullControl.All",
		"RoleManagement.ReadWrite.Directory",
		"admin:org",                // GitHub org admin
		"delete_repo",              // GitHub repo deletion
		"workflow",                 // GitHub CI tampering
		"im:history",               // Slack DMs
		"https://mail.google.com/", // full mailbox
		"Mail.Read",
	}
	for _, s := range sensitive {
		if !isSensitive(s) {
			t.Errorf("scope %q should be classified sensitive (FN)", s)
		}
	}
}

func TestIsSensitive_BenignFPGuard(t *testing.T) {
	// FP guard: identity-only scopes must NOT be sensitive even though some contain "mail".
	benign := []string{
		"openid", "profile", "email", "user:email", "users:read.email",
		"https://www.googleapis.com/auth/userinfo.email",
		"https://www.googleapis.com/auth/userinfo.profile",
	}
	for _, s := range benign {
		if isSensitive(s) {
			t.Errorf("identity scope %q must NOT be classified sensitive (FP)", s)
		}
	}
}

func TestAccuracy_ScopeCorpus(t *testing.T) {
	s := ScoreScopes(ScopeCorpus())
	t.Logf("shadow-IT sensitive-scope accuracy: recall=%.2f precision=%.2f (TP=%d FN=%d FP=%d TN=%d)",
		s.Recall(), s.Precision(), s.TP, s.FN, s.FP, s.TN)

	// The bar: every high-risk scope is flagged (recall 1.0 — the FN-expansion in #322) and no
	// identity/narrow scope is flagged (precision 1.0 — the OIDC-`email` FP guard). Measures both
	// axes + regression-guards the whole taxonomy.
	if s.Recall() != 1.0 {
		t.Errorf("sensitive-scope recall must be 1.0, got %.2f (FN=%d)", s.Recall(), s.FN)
	}
	if s.Precision() != 1.0 {
		t.Errorf("sensitive-scope precision must be 1.0 (no identity-scope FP), got %.2f (FP=%d)", s.Precision(), s.FP)
	}
}
