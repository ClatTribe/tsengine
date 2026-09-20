package operate

import (
	"testing"
	"time"
)

// The admin-scope grant finding carries the provider's own client id and user ids in ToolArgs when
// the fetcher reported them — the identifiers a live revoke names — and nothing when it did not.
func TestOAuthAdminScopeFindingCarriesGrantIdentifiers(t *testing.T) {
	ws := Workspace{OAuthGrants: []OAuthGrant{
		{App: "Shadow Admin", Scopes: []string{"okta.users.manage"}, Users: 2, AdminScope: true, Verified: true, ClientID: "0oa-app", UserIDs: []string{"00u-1", "00u-2"}},
		{App: "Label Only", Scopes: []string{"okta.users.manage"}, Users: 1, AdminScope: true, Verified: true},
	}}
	n := 0
	fs := checkOAuthGrants(ws, time.Now(), func() string { n++; return "f" })
	if len(fs) != 2 {
		t.Fatalf("want two admin-scope findings, got %d", len(fs))
	}
	byApp := map[string]map[string]string{}
	for _, f := range fs {
		byApp[f.Endpoint] = f.ToolArgs
	}
	if byApp["Shadow Admin"]["client_id"] != "0oa-app" || byApp["Shadow Admin"]["user_ids"] != "00u-1,00u-2" {
		t.Errorf("identifiers not stamped: %v", byApp["Shadow Admin"])
	}
	if len(byApp["Label Only"]) != 0 {
		t.Errorf("a grant with no identifiers must stamp nothing (the remediation stays a runbook): %v", byApp["Label Only"])
	}
}
