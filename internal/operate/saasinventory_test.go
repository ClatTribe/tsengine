package operate

import "testing"

func TestSaaSInventory_FromLiveGrants(t *testing.T) {
	ws := Workspace{OAuthGrants: []OAuthGrant{
		{App: "Loom", Scopes: []string{"profile", "drive.readonly"}, Users: 3, Verified: false},
		{App: "Okta", Scopes: []string{"openid"}, Users: 1, Verified: true},
		{App: "AdminBot", Scopes: []string{"https://www.googleapis.com/auth/admin.directory.user"}, Users: 1, AdminScope: true, Verified: true},
	}}
	apps, sum := SaaSInventory(ws)

	if sum.TotalApps != 3 {
		t.Fatalf("inventory should discover all 3 apps, got %d", sum.TotalApps)
	}
	// Loom: a sensitive scope (drive) + unverified + multi-user.
	if sum.SensitiveApps < 2 { // Loom (drive) + AdminBot (admin scope)
		t.Errorf("expected >=2 sensitive apps (drive + admin scope), got %d", sum.SensitiveApps)
	}
	if sum.UnverifiedApps != 1 {
		t.Errorf("only Loom is unverified, got %d", sum.UnverifiedApps)
	}
	if sum.MultiUserApps != 1 { // only Loom has >=2 users
		t.Errorf("only Loom is multi-user, got %d", sum.MultiUserApps)
	}
	// Honesty: no shadow-IT verdict, since operate carries no admin-consent data.
	if sum.ShadowITApps != 0 {
		t.Errorf("operate has no consent data → no shadow-IT verdict, got %d", sum.ShadowITApps)
	}
	for _, a := range apps {
		if a.ShadowIT {
			t.Errorf("%s must not be labeled shadow IT without consent data", a.Name)
		}
	}
}

func TestSaaSInventory_EmptyWorkspace(t *testing.T) {
	apps, sum := SaaSInventory(Workspace{})
	if len(apps) != 0 || sum.TotalApps != 0 {
		t.Errorf("an empty workspace yields an empty inventory, got %d apps", len(apps))
	}
}
