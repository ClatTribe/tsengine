package platformapi

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/ClatTribe/tsengine/internal/connector"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

func TestSetLoginFlow_StoresValidatedFlow(t *testing.T) {
	st := store.NewMemory()
	ctx := context.Background()
	_ = st.PutAsset(ctx, platform.Asset{ID: "a-web", TenantID: "t1", Type: "web_application", Target: "https://app.acme.com"})
	h := NewHandler(Deps{Store: st, Connectors: connector.NewRegistry(), Token: "platform-tok"})

	// A valid recorded flow → stored.
	flow := `{"type":"recorded","steps":[{"method":"POST","url":"https://app.acme.com/login","fields":{"u":"x","p":"y"}}],"validate_url":"https://app.acme.com/me","success_marker":"Sign out"}`
	rec := do(h, "POST", "/v1/assets/a-web/login-flow", "t1", flow)
	if rec.Code != 200 {
		t.Fatalf("valid flow should be accepted, got %d: %s", rec.Code, rec.Body.String())
	}
	// Persisted in the asset Meta as JSON.
	assets, _ := st.ListAssets(ctx, "t1")
	if assets[0].Meta["login_flow"] == "" {
		t.Error("the login flow should be persisted in the asset")
	}
	var stored map[string]any
	_ = json.Unmarshal([]byte(assets[0].Meta["login_flow"]), &stored)
	if stored["type"] != "recorded" {
		t.Errorf("stored flow type wrong: %v", stored["type"])
	}
}

func TestSetLoginFlow_Validation(t *testing.T) {
	st := store.NewMemory()
	_ = st.PutAsset(context.Background(), platform.Asset{ID: "a-web", TenantID: "t1", Type: "web_application"})
	h := NewHandler(Deps{Store: st, Connectors: connector.NewRegistry(), Token: "platform-tok"})

	// A token flow with no token → 400.
	if rec := do(h, "POST", "/v1/assets/a-web/login-flow", "t1", `{"type":"token"}`); rec.Code != 400 {
		t.Errorf("a token flow with no token should 400, got %d", rec.Code)
	}
	// An unknown type → 400.
	if rec := do(h, "POST", "/v1/assets/a-web/login-flow", "t1", `{"type":"magic"}`); rec.Code != 400 {
		t.Errorf("an unknown auth type should 400, got %d", rec.Code)
	}
	// A recorded flow with a step missing a URL → 400.
	if rec := do(h, "POST", "/v1/assets/a-web/login-flow", "t1", `{"type":"recorded","steps":[{"method":"POST"}]}`); rec.Code != 400 {
		t.Errorf("a step with no url should 400, got %d", rec.Code)
	}
	// Unknown asset → 404.
	if rec := do(h, "POST", "/v1/assets/nope/login-flow", "t1", `{"type":"token","token":"t"}`); rec.Code != 404 {
		t.Errorf("an unknown asset should 404, got %d", rec.Code)
	}
}
