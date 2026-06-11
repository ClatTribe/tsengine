package platformapi

import (
	"context"
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/internal/connector"
	"github.com/ClatTribe/tsengine/internal/runner"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

func TestIncidents_ReturnsOpenOnly(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	_ = st.PutIncident(ctx, platform.Incident{ID: "i1", TenantID: "t1", Title: "Admin no MFA", Severity: "critical", Status: platform.IncidentOpen})
	_ = st.PutIncident(ctx, platform.Incident{ID: "i2", TenantID: "t1", Title: "Old issue", Severity: "high", Status: platform.IncidentResolved})
	// isolation: another tenant's incident must never appear
	_ = st.PutIncident(ctx, platform.Incident{ID: "i3", TenantID: "t2", Title: "Other tenant", Severity: "critical", Status: platform.IncidentOpen})

	h := NewHandler(Deps{Store: st, Connectors: connector.NewRegistry(), Token: "platform-tok"})

	rec := do(h, "GET", "/v1/incidents", "t1", "")
	if rec.Code != 200 {
		t.Fatalf("want 200, got %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "Admin no MFA") {
		t.Error("open incident should be listed")
	}
	if strings.Contains(body, "Old issue") {
		t.Error("resolved incident must not appear without ?status=all")
	}
	if strings.Contains(body, "Other tenant") {
		t.Error("tenant isolation breached: another tenant's incident leaked")
	}

	all := do(h, "GET", "/v1/incidents?status=all", "t1", "")
	if !strings.Contains(all.Body.String(), "Old issue") {
		t.Error("?status=all should include resolved incidents")
	}
}

func TestRescan_RunsTenantScan(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	_ = st.PutTenant(ctx, platform.Tenant{ID: "t1"})
	_ = st.PutAsset(ctx, platform.Asset{ID: "a1", TenantID: "t1", Type: "workspace", Target: "acme"})
	svc := &runner.Service{Store: st, Connectors: connector.NewRegistry(), Tokens: fakeTokens{}, Scanner: fakeScanner{}}
	h := NewHandler(Deps{Store: st, Connectors: connector.NewRegistry(), Runner: svc, Token: "platform-tok"})

	rec := do(h, "POST", "/v1/rescan", "t1", "")
	if rec.Code != 200 {
		t.Fatalf("rescan should return 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "assets_scanned") {
		t.Errorf("response should report assets_scanned, got %s", rec.Body.String())
	}
}
