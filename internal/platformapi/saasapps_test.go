package platformapi

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/ClatTribe/tsengine/internal/connector"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

func TestHandleSaaSApps_DiscoveryView(t *testing.T) {
	st := store.NewMemory()
	ctx := context.Background()
	// Persisted (per operate scan) third-party apps for the tenant, across providers.
	_ = st.ReplaceThirdPartyApps(ctx, "t1", "gworkspace", []platform.ThirdPartyApp{
		{TenantID: "t1", Provider: "gworkspace", AppID: "Loom", Scopes: []string{"drive.readonly"}, Users: 4, Verified: false},
		{TenantID: "t1", Provider: "gworkspace", AppID: "AdminBot", Scopes: []string{"admin.directory.user"}, Users: 1, AdminScope: true, Verified: true},
	})
	_ = st.ReplaceThirdPartyApps(ctx, "t1", "okta", []platform.ThirdPartyApp{
		{TenantID: "t1", Provider: "okta", AppID: "SSO", Scopes: []string{"openid"}, Users: 50, Verified: true},
	})
	// Another tenant's apps must never leak.
	_ = st.ReplaceThirdPartyApps(ctx, "t2", "okta", []platform.ThirdPartyApp{
		{TenantID: "t2", Provider: "okta", AppID: "OTHER", Scopes: []string{"admin"}, Users: 1, AdminScope: true},
	})

	h := NewHandler(Deps{Store: st, Connectors: connector.NewRegistry(), Token: "platform-tok"})
	rec := do(h, "GET", "/v1/saas-apps", "t1", "")
	if rec.Code != 200 {
		t.Fatalf("want 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Apps []struct {
			Name      string `json:"name"`
			Count     int    `json:"count"`
			Sensitive bool   `json:"sensitive"`
			ShadowIT  bool   `json:"shadow_it"`
		} `json:"apps"`
		Summary struct {
			TotalApps      int `json:"total_apps"`
			SensitiveApps  int `json:"sensitive_apps"`
			UnverifiedApps int `json:"unverified_apps"`
			ShadowITApps   int `json:"shadow_it_apps"`
			MultiUserApps  int `json:"multi_user_apps"`
		} `json:"summary"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Summary.TotalApps != 3 {
		t.Errorf("tenant t1 has 3 SaaS apps, got %d", resp.Summary.TotalApps)
	}
	if resp.Summary.SensitiveApps < 2 { // Loom (drive) + AdminBot (admin scope)
		t.Errorf("expected >=2 sensitive apps, got %d", resp.Summary.SensitiveApps)
	}
	if resp.Summary.MultiUserApps != 2 { // Loom (4) + SSO (50)
		t.Errorf("expected 2 multi-user apps, got %d", resp.Summary.MultiUserApps)
	}
	// Honesty: no shadow-IT verdict without consent data.
	if resp.Summary.ShadowITApps != 0 {
		t.Errorf("no consent data → no shadow-IT verdict, got %d", resp.Summary.ShadowITApps)
	}
	// Tenant isolation: t2's app must not appear.
	for _, a := range resp.Apps {
		if a.Name == "OTHER" {
			t.Error("another tenant's app leaked into the SaaS inventory")
		}
	}
}
