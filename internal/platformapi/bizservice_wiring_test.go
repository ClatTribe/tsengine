package platformapi

import (
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/ledger"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

// ADR 0028 G2 wiring — the seam, which is where this session's defects have lived.

func TestBusinessServices_EmptyIsAPromptAndDeclaringOneGroups(t *testing.T) {
	st := store.NewMemory()
	d := Deps{Store: st, Token: "platform-tok", Recorder: ledger.NewRecorder(),
		NewID: func() string { return "svc-1" }}
	ctx := t.Context()
	if err := st.PutTenant(ctx, platform.Tenant{ID: "t1"}); err != nil {
		t.Fatal(err)
	}
	if err := st.PutAsset(ctx, platform.Asset{ID: "a1", TenantID: "t1", Target: "checkout.acme.com", Type: "web_application"}); err != nil {
		t.Fatal(err)
	}
	h := NewHandler(d)

	body := do(h, "GET", "/v1/business-services", "t1", "").Body.String()
	if !strings.Contains(body, "is checkout at risk") {
		t.Errorf("the unmapped state should ask the question rather than render an empty list: %s", body)
	}

	if rec := do(h, "PUT", "/v1/settings/business-services", "t1",
		`{"services":[{"name":"Checkout","criticality":"critical","owner":"payments","asset_ids":["a1"]}]}`); rec.Code != 200 {
		t.Fatalf("set: %d %s", rec.Code, rec.Body.String())
	}

	body = do(h, "GET", "/v1/business-services", "t1", "").Body.String()
	if !strings.Contains(body, "Checkout") {
		t.Fatalf("the declared service is not in the view — the seam is broken: %s", body)
	}
	// No engagement has completed, so the service must read as unassessed rather than clean.
	if !strings.Contains(body, "nobody has looked") {
		t.Errorf("a service whose assets were never scanned must not read as clean: %s", body)
	}
}

func TestSetBusinessServices_RefusesAnUnnamedService(t *testing.T) {
	st := store.NewMemory()
	d := Deps{Store: st, Token: "platform-tok"}
	if err := st.PutTenant(t.Context(), platform.Tenant{ID: "t1"}); err != nil {
		t.Fatal(err)
	}
	rec := do(NewHandler(d), "PUT", "/v1/settings/business-services", "t1", `{"services":[{"asset_ids":["a1"]}]}`)
	if rec.Code != 400 {
		t.Errorf("an unnamed service was accepted (%d) — it cannot be routed to an owner, which is the "+
			"only reason to declare one", rec.Code)
	}
}
