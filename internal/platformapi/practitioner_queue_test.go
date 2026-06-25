package platformapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ClatTribe/tsengine/internal/practitioner"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// The practitioner desk aggregates ONLY the tenants where the practitioner is a named practitioner of
// record — it never reads a tenant they are not assigned to (the cross-tenant isolation proof).
func TestPractitionerQueue_OnlyAssignedTenants(t *testing.T) {
	st := store.NewMemory()
	ctx := context.Background()
	// tenant A names Dana; tenant B does NOT.
	_ = st.PutTenant(ctx, platform.Tenant{ID: "tA", Name: "Acme", Practitioners: []platform.Practitioner{{Name: "Dana", Email: "dana@x.io", Capacity: platform.CapacityManaged}}})
	_ = st.PutTenant(ctx, platform.Tenant{ID: "tB", Name: "Other"})
	// a proposed risk in BOTH tenants
	_ = st.PutRisk(ctx, platform.Risk{ID: "ra", TenantID: "tA", Title: "A risk", Status: platform.RiskOpen, Proposed: true})
	_ = st.PutRisk(ctx, platform.Risk{ID: "rb", TenantID: "tB", Title: "B risk", Status: platform.RiskOpen, Proposed: true})
	_ = st.PutFinding(ctx, "tA", types.Finding{ID: "f", Severity: types.SeverityHigh})

	d := Deps{Store: st, Token: "op-token"}

	req := httptest.NewRequest(http.MethodGet, "/v1/practitioner/queue?practitioner=dana@x.io", nil)
	rec := httptest.NewRecorder()
	d.handlePractitionerQueue(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("queue: %d %s", rec.Code, rec.Body.String())
	}
	var out struct {
		TenantsServed int                    `json:"tenants_served"`
		Items         []practitioner.Pending `json:"items"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if out.TenantsServed != 1 {
		t.Fatalf("Dana serves only tenant A, got tenants_served=%d", out.TenantsServed)
	}
	for _, it := range out.Items {
		if it.TenantID != "tA" {
			t.Errorf("ISOLATION: queue surfaced an item from an unassigned tenant: %+v", it)
		}
	}
	if len(out.Items) == 0 {
		t.Error("expected the assigned tenant's pending risk in the queue")
	}

	// missing practitioner param → 400
	bad := httptest.NewRequest(http.MethodGet, "/v1/practitioner/queue", nil)
	brec := httptest.NewRecorder()
	d.handlePractitionerQueue(brec, bad)
	if brec.Code != http.StatusBadRequest {
		t.Errorf("missing practitioner must be 400, got %d", brec.Code)
	}
}

// The operator platform token gates the desk — a tenant session cannot reach it.
func TestPractitionerQueue_OperatorGated(t *testing.T) {
	d := Deps{Store: store.NewMemory(), Token: "op-token"}
	h := d.platformAuth(d.handlePractitionerQueue)

	// no token → 401
	r1 := httptest.NewRequest(http.MethodGet, "/v1/practitioner/queue?practitioner=x", nil)
	w1 := httptest.NewRecorder()
	h(w1, r1)
	if w1.Code != http.StatusUnauthorized {
		t.Errorf("no operator token must be 401, got %d", w1.Code)
	}
	// operator token → allowed (200 with empty queue)
	r2 := httptest.NewRequest(http.MethodGet, "/v1/practitioner/queue?practitioner=x", nil)
	r2.Header.Set("Authorization", "Bearer op-token")
	w2 := httptest.NewRecorder()
	h(w2, r2)
	if w2.Code != http.StatusOK {
		t.Errorf("operator token must reach the desk, got %d", w2.Code)
	}
}
