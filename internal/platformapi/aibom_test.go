package platformapi

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/pkg/platform"
)

func TestWriteScopeClassifier(t *testing.T) {
	for _, s := range []string{"repo", "okta.users.manage", "admin.directory.user", "factors.write", "users.lifecycle", "Files.ReadWrite"} {
		if !writeScope(s) {
			t.Errorf("%q should classify as write-capable", s)
		}
	}
	for _, s := range []string{"read:org", "okta.users.read", "admin.directory.user.readonly", "openid", "User.Read.All"} {
		if writeScope(s) {
			t.Errorf("%q should classify as read-only", s)
		}
	}
}

func TestBuildAIBOM_Summary(t *testing.T) {
	conns := []platform.Connection{
		{Kind: "github", Account: "acme", Status: "active", Scopes: []string{"repo", "read:org"}},
		{Kind: "gworkspace", Account: "acme.com", Status: "active", Scopes: []string{"admin.directory.user.readonly"}},
		{Kind: "okta", Account: "acme", Status: "active", Scopes: []string{"okta.users.read", "okta.factors.read"}},
	}
	bom := buildAIBOM(platform.Tenant{ID: "t", AgentsHalted: true}, conns)

	if !bom.Governance.KillSwitchEngaged || bom.Governance.GateTier != platform.GateTier {
		t.Errorf("governance wrong: %+v", bom.Governance)
	}
	if bom.Summary.Connections != 3 || bom.Summary.WriteCapable != 1 || bom.Summary.ReadOnly != 2 {
		t.Errorf("summary wrong: %+v", bom.Summary)
	}
	if bom.Connections[0].Capability != "read-write" || len(bom.Connections[0].WriteScopes) != 1 || bom.Connections[0].WriteScopes[0] != "repo" {
		t.Errorf("github should be read-write via `repo`: %+v", bom.Connections[0])
	}
	if bom.Connections[1].Capability != "read-only" || len(bom.Connections[1].WriteScopes) != 0 {
		t.Errorf("gworkspace readonly should be read-only: %+v", bom.Connections[1])
	}
}

func TestAIBOMEndpoint(t *testing.T) {
	h, st := setup(t)
	ctx := context.Background()
	_ = st.PutConnection(ctx, platform.Connection{ID: "ok", TenantID: "t1", Kind: "okta", Status: "active", Scopes: []string{"okta.users.read"}})
	tn, _ := st.GetTenant(ctx, "t1")
	tn.AgentsHalted = true
	_ = st.PutTenant(ctx, tn)

	rec := do(h, "GET", "/v1/ai-bom", "t1", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("ai-bom: want 200, got %d (%s)", rec.Code, rec.Body.String())
	}
	var bom AIBOM
	if err := json.Unmarshal(rec.Body.Bytes(), &bom); err != nil {
		t.Fatal(err)
	}
	if !bom.Governance.KillSwitchEngaged {
		t.Error("governance must reflect the engaged kill-switch")
	}
	if bom.Summary.Connections < 1 {
		t.Errorf("should list the tenant's connections: %+v", bom.Summary)
	}
	// the manifest describes permission breadth, never the token — no secret ref leaks
	if strings.Contains(rec.Body.String(), "vault:") || strings.Contains(rec.Body.String(), "secret_ref") {
		t.Errorf("ai-bom must not leak secret refs: %s", rec.Body.String())
	}
}
