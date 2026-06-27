package platformapi

import (
	"context"
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/internal/connector"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

func TestOwnershipChallenge_IssuesAndPersistsToken(t *testing.T) {
	st := store.NewMemory()
	ctx := context.Background()
	_ = st.PutAsset(ctx, platform.Asset{ID: "a-web", TenantID: "t1", Type: "web_application", Target: "https://app.acme.com"})
	h := NewHandler(Deps{Store: st, Connectors: connector.NewRegistry(), Token: "platform-tok"})

	rec := do(h, "POST", "/v1/assets/a-web/ownership/challenge", "t1", "")
	if rec.Code != 200 {
		t.Fatalf("challenge should be 200, got %d: %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, "_tsengine.app.acme.com") || !strings.Contains(body, "tsengine-site-verification=") {
		t.Errorf("challenge should carry the DNS instructions, got %s", body)
	}
	assets, _ := st.ListAssets(ctx, "t1")
	tok := assets[0].Meta["ownership_token"]
	if tok == "" {
		t.Fatal("the token should be persisted on the asset")
	}
	// Idempotent: a second challenge returns the SAME token (so an in-flight DNS record stays valid).
	rec2 := do(h, "POST", "/v1/assets/a-web/ownership/challenge", "t1", "")
	if !strings.Contains(rec2.Body.String(), tok) {
		t.Error("re-issuing a challenge should return the same token")
	}
}

// Verify before a challenge was issued → 400 (no token to check against). Grounded: we never claim
// verified without a real token + a real check.
func TestOwnershipVerify_RequiresChallengeFirst(t *testing.T) {
	st := store.NewMemory()
	_ = st.PutAsset(context.Background(), platform.Asset{ID: "a-web", TenantID: "t1", Type: "web_application", Target: "https://app.acme.com"})
	h := NewHandler(Deps{Store: st, Connectors: connector.NewRegistry(), Token: "platform-tok"})

	if rec := do(h, "POST", "/v1/assets/a-web/ownership/verify", "t1", ""); rec.Code != 400 {
		t.Errorf("verify without a challenge should 400, got %d", rec.Code)
	}
}

// Tenant isolation: a tenant cannot challenge another tenant's asset (it's not in their list → 404).
func TestOwnership_TenantScoped(t *testing.T) {
	st := store.NewMemory()
	_ = st.PutAsset(context.Background(), platform.Asset{ID: "a-web", TenantID: "t1", Type: "web_application", Target: "https://app.acme.com"})
	h := NewHandler(Deps{Store: st, Connectors: connector.NewRegistry(), Token: "platform-tok"})

	if rec := do(h, "POST", "/v1/assets/a-web/ownership/challenge", "t2", ""); rec.Code != 404 {
		t.Errorf("another tenant must not reach the asset, got %d", rec.Code)
	}
}
