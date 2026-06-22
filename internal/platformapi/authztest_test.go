package platformapi

import (
	"context"
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/internal/connector"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

func TestSetAuthzTest_StoresValidatedConfig(t *testing.T) {
	st := store.NewMemory()
	ctx := context.Background()
	_ = st.PutAsset(ctx, platform.Asset{ID: "a-api", TenantID: "t1", Type: "api", Target: "https://api.acme.com"})
	h := NewHandler(Deps{Store: st, Connectors: connector.NewRegistry(), Token: "platform-tok"})

	cfg := `{
	  "victim":   {"name":"victim","headers":{"Authorization":"Bearer A"}},
	  "attacker": {"name":"attacker","headers":{"Authorization":"Bearer B"}},
	  "operations": [{"method":"GET","url":"https://api.acme.com/invoices/42","class":"bola","marker":"victim@acme.com"}]
	}`
	rec := do(h, "POST", "/v1/assets/a-api/authz-test", "t1", cfg)
	if rec.Code != 200 {
		t.Fatalf("valid config should be accepted, got %d: %s", rec.Code, rec.Body.String())
	}
	assets, _ := st.ListAssets(ctx, "t1")
	stored := assets[0].Meta["authz_test"]
	if stored == "" {
		t.Fatal("the authz-test config should be persisted in the asset")
	}
	// The persisted blob holds the operation but the API response must not echo headers.
	if !strings.Contains(stored, "invoices/42") {
		t.Error("the operation should be persisted")
	}
	if strings.Contains(rec.Body.String(), "Bearer") {
		t.Error("the API response must NOT echo the identities' auth headers")
	}
}

func TestSetAuthzTest_Validation(t *testing.T) {
	st := store.NewMemory()
	_ = st.PutAsset(context.Background(), platform.Asset{ID: "a-api", TenantID: "t1", Type: "api"})
	h := NewHandler(Deps{Store: st, Connectors: connector.NewRegistry(), Token: "platform-tok"})

	// Missing attacker auth → 400.
	if rec := do(h, "POST", "/v1/assets/a-api/authz-test", "t1",
		`{"victim":{"headers":{"Authorization":"A"}},"attacker":{},"operations":[{"method":"GET","url":"u","class":"bola"}]}`); rec.Code != 400 {
		t.Errorf("missing attacker auth should 400, got %d", rec.Code)
	}
	// No operations → 400.
	if rec := do(h, "POST", "/v1/assets/a-api/authz-test", "t1",
		`{"victim":{"headers":{"Authorization":"A"}},"attacker":{"headers":{"Authorization":"B"}},"operations":[]}`); rec.Code != 400 {
		t.Errorf("no operations should 400, got %d", rec.Code)
	}
	// Bad operation class → 400.
	if rec := do(h, "POST", "/v1/assets/a-api/authz-test", "t1",
		`{"victim":{"headers":{"Authorization":"A"}},"attacker":{"headers":{"Authorization":"B"}},"operations":[{"method":"GET","url":"u","class":"mass_assignment"}]}`); rec.Code != 400 {
		t.Errorf("a non-authz operation class should 400, got %d", rec.Code)
	}
	// Unknown asset → 404.
	if rec := do(h, "POST", "/v1/assets/nope/authz-test", "t1",
		`{"victim":{"headers":{"Authorization":"A"}},"attacker":{"headers":{"Authorization":"B"}},"operations":[{"method":"GET","url":"u","class":"bola"}]}`); rec.Code != 404 {
		t.Errorf("unknown asset should 404, got %d", rec.Code)
	}
}
