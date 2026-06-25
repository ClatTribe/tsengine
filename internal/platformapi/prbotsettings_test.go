package platformapi

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/ClatTribe/tsengine/internal/connector"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

func TestPRBotSettings_DefaultThenSet(t *testing.T) {
	st := store.NewMemory()
	ctx := context.Background()
	_ = st.PutTenant(ctx, platform.Tenant{ID: "t1", Name: "Acme"})
	h := NewHandler(Deps{Store: st, Connectors: connector.NewRegistry(), Token: "platform-tok"})

	// Default: disabled, off.
	rec := do(h, "GET", "/v1/settings/pr-bot", "t1", "")
	if rec.Code != 200 {
		t.Fatalf("GET should be 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var got map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &got)
	if got["enabled"] != false || got["block_severity"] != "off" {
		t.Errorf("default policy wrong: %v", got)
	}
	if got["github_connected"] != false {
		t.Errorf("no GitHub connection should report github_connected=false, got %v", got["github_connected"])
	}

	// Set: enabled, block at high.
	rec = do(h, "PUT", "/v1/settings/pr-bot", "t1", `{"enabled":true,"block_severity":"high"}`)
	if rec.Code != 200 {
		t.Fatalf("PUT should be 200, got %d: %s", rec.Code, rec.Body.String())
	}
	tn, _ := st.GetTenant(ctx, "t1")
	if tn.PRBot == nil || !tn.PRBot.Enabled || tn.PRBot.BlockSeverity != "high" {
		t.Errorf("policy not persisted: %+v", tn.PRBot)
	}

	// GET reflects it.
	rec = do(h, "GET", "/v1/settings/pr-bot", "t1", "")
	_ = json.Unmarshal(rec.Body.Bytes(), &got)
	if got["enabled"] != true || got["block_severity"] != "high" {
		t.Errorf("GET did not reflect the saved policy: %v", got)
	}
}

func TestPRBotSettings_Validation(t *testing.T) {
	st := store.NewMemory()
	_ = st.PutTenant(context.Background(), platform.Tenant{ID: "t1", Name: "Acme"})
	h := NewHandler(Deps{Store: st, Connectors: connector.NewRegistry(), Token: "platform-tok"})

	// A bogus severity → 400.
	if rec := do(h, "PUT", "/v1/settings/pr-bot", "t1", `{"enabled":true,"block_severity":"sometimes"}`); rec.Code != 400 {
		t.Errorf("a bogus block_severity should 400, got %d", rec.Code)
	}
	// "off" is accepted and normalizes to comment-only (empty).
	if rec := do(h, "PUT", "/v1/settings/pr-bot", "t1", `{"enabled":true,"block_severity":"off"}`); rec.Code != 200 {
		t.Errorf("off should be accepted, got %d", rec.Code)
	}
	tn, _ := st.GetTenant(context.Background(), "t1")
	if tn.PRBot.BlockSeverity != "" {
		t.Errorf(`"off" should normalize to comment-only (empty), got %q`, tn.PRBot.BlockSeverity)
	}
}
