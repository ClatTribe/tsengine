package platformapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/pkg/platform"
)

// The fulfilment half of the contact-sales upgrade: before this endpoint existed a plan could
// only be set at tenant CREATION, so a customer who signed up free could never be moved to a
// paid plan by any supported path.
func TestSetTenantPlan_UpgradesExistingTenant(t *testing.T) {
	h, st := setup(t)

	rec := do(h, http.MethodPost, "/v1/tenants/t1/plan", "", `{"plan":"growth","note":"INV-2026-014"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rec.Code, rec.Body)
	}
	var body struct {
		Plan         string `json:"plan"`
		PreviousPlan string `json:"previous_plan"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Plan != platform.PlanGrowth {
		t.Fatalf("plan=%q want growth", body.Plan)
	}
	// and it actually persisted
	got, err := st.GetTenant(context.Background(), "t1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Plan != platform.PlanGrowth {
		t.Fatalf("stored plan=%q want growth", got.Plan)
	}
	// The upgrade must actually change entitlements. Note Growth ("Core") is deliberately
	// AIEnabled:false — operator-funded AI is Enterprise-only — so the asset cap is what moves.
	if free, paid := platform.Entitlements(platform.PlanFree), platform.Entitlements(got.Plan); paid.MaxAssets <= free.MaxAssets {
		t.Fatalf("upgrade had no effect: max_assets %d -> %d", free.MaxAssets, paid.MaxAssets)
	}
}

// Enterprise is the tier that unlocks the operator-funded AI agents.
func TestSetTenantPlan_EnterpriseUnlocksAI(t *testing.T) {
	h, st := setup(t)
	if rec := do(h, http.MethodPost, "/v1/tenants/t1/plan", "", `{"plan":"enterprise"}`); rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rec.Code, rec.Body)
	}
	got, _ := st.GetTenant(context.Background(), "t1")
	ent := platform.Entitlements(got.Plan)
	if !ent.AIEnabled || ent.MaxAssets != -1 {
		t.Fatalf("enterprise should unlock AI and uncap assets, got %+v", ent)
	}
}

// A typo must not silently downgrade a customer who just paid.
func TestSetTenantPlan_RejectsUnknownPlan(t *testing.T) {
	h, st := setup(t)
	_ = st.PutTenant(context.Background(), platform.Tenant{ID: "t1", Name: "Acme", Plan: platform.PlanGrowth})

	rec := do(h, http.MethodPost, "/v1/tenants/t1/plan", "", `{"plan":"groth"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("want 400 for a typo, got %d: %s", rec.Code, rec.Body)
	}
	got, _ := st.GetTenant(context.Background(), "t1")
	if got.Plan != platform.PlanGrowth {
		t.Fatalf("a rejected write must not change the plan; got %q", got.Plan)
	}
}

// THE security property: the economic gate must not be self-serve bypassable. A tenant session
// (no platform token) must never be able to upgrade itself.
func TestSetTenantPlan_TenantCannotUpgradeItself(t *testing.T) {
	h, st := setup(t)

	req := httptest.NewRequest(http.MethodPost, "/v1/tenants/t1/plan", strings.NewReader(`{"plan":"enterprise"}`))
	req.Header.Set("X-Tenant-ID", "t1") // tenant header but NO platform bearer token
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("a tenant must not upgrade itself; got %d: %s", rec.Code, rec.Body)
	}
	got, _ := st.GetTenant(context.Background(), "t1")
	if platform.Entitlements(got.Plan).AIEnabled {
		t.Fatal("self-upgrade changed entitlements — the economic gate is bypassable")
	}
}

// A plan-blocked customer must be given somewhere to go, not a dead end.
func TestEntitlementBlocked_IsActionable(t *testing.T) {
	rec := httptest.NewRecorder()
	entitlementBlocked(rec, "asset_limit", "the Free plan includes up to 3 scan targets")

	if rec.Code != http.StatusPaymentRequired {
		t.Fatalf("want 402, got %d", rec.Code)
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["upgrade_url"] != upgradeContactPath {
		t.Errorf("402 must carry a real destination, got %v", body["upgrade_url"])
	}
	if body["reason"] != "asset_limit" {
		t.Errorf("402 must carry a machine-readable reason, got %v", body["reason"])
	}
	// Honesty: there is no self-serve checkout, so the response must say so.
	if body["upgrade_kind"] != "contact_sales" {
		t.Errorf("402 must not imply a checkout that does not exist, got %v", body["upgrade_kind"])
	}
}
