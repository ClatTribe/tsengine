package runner

import (
	"context"
	"testing"

	"github.com/ClatTribe/tsengine/internal/operate"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

// wsSource returns a fixed workspace (with grants) for the inventory test.
type wsSource struct{ ws operate.Workspace }

func (s wsSource) Workspace(context.Context, platform.Asset) (operate.Workspace, error) {
	return s.ws, nil
}

func TestOperateRunner_PersistsAppInventory(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	src := wsSource{ws: operate.Workspace{Provider: "okta", OAuthGrants: []operate.OAuthGrant{
		{App: "Risky Tool", Scopes: []string{"okta.users.manage"}, Users: 2, AdminScope: true, Verified: false},
		{App: "Calendar", Scopes: []string{"okta.users.read"}, Users: 5, AdminScope: false, Verified: true},
	}}}
	or := &OperateRunner{Source: src, Apps: st}

	if _, err := or.Scan(ctx, platform.Asset{TenantID: "t1", Type: WorkspaceType, Target: "acme"}); err != nil {
		t.Fatal(err)
	}
	apps, _ := st.ListThirdPartyApps(ctx, "t1")
	if len(apps) != 2 {
		t.Fatalf("the scan should persist 2 apps, got %d", len(apps))
	}
	by := map[string]platform.ThirdPartyApp{}
	for _, a := range apps {
		by[a.AppID] = a
	}
	if a := by["Risky Tool"]; !a.AdminScope || a.Verified || a.Users != 2 || a.Provider != "okta" {
		t.Errorf("Risky Tool inventory wrong: %+v", a)
	}

	// a re-scan where "Risky Tool" was revoked → it disappears (replace semantics)
	src.ws.OAuthGrants = []operate.OAuthGrant{{App: "Calendar", Scopes: []string{"okta.users.read"}, Users: 5, Verified: true}}
	or2 := &OperateRunner{Source: src, Apps: st}
	if _, err := or2.Scan(ctx, platform.Asset{TenantID: "t1", Type: WorkspaceType, Target: "acme"}); err != nil {
		t.Fatal(err)
	}
	apps, _ = st.ListThirdPartyApps(ctx, "t1")
	if len(apps) != 1 || apps[0].AppID != "Calendar" {
		t.Errorf("a revoked app should disappear on re-scan, got %+v", apps)
	}
}

// No AppSink wired → no inventory persisted (purely additive).
func TestOperateRunner_NoSinkNoInventory(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	or := &OperateRunner{Source: wsSource{ws: operate.Workspace{Provider: "okta", OAuthGrants: []operate.OAuthGrant{{App: "X"}}}}}
	if _, err := or.Scan(ctx, platform.Asset{TenantID: "t1", Type: WorkspaceType}); err != nil {
		t.Fatal(err)
	}
	apps, _ := st.ListThirdPartyApps(ctx, "t1")
	if len(apps) != 0 {
		t.Errorf("no sink → no inventory, got %d", len(apps))
	}
}
