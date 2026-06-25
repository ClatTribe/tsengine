package platformapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

func operatorDeps(t *testing.T) Deps {
	t.Helper()
	st := store.NewMemory()
	ctx := context.Background()
	// tenant A names dana@x.io as a managed practitioner; tenant B does not.
	_ = st.PutTenant(ctx, platform.Tenant{ID: "tA", Name: "Acme", Practitioners: []platform.Practitioner{{Name: "Dana", Email: "dana@x.io", Capacity: platform.CapacityManaged}}})
	_ = st.PutTenant(ctx, platform.Tenant{ID: "tB", Name: "Other"})
	_ = st.PutRisk(ctx, platform.Risk{ID: "ra", TenantID: "tA", Title: "A risk", Status: platform.RiskOpen, Proposed: true})
	_ = st.PutRisk(ctx, platform.Risk{ID: "rb", TenantID: "tB", Title: "B risk", Status: platform.RiskOpen, Proposed: true})
	n := 0
	return Deps{Store: st, Token: "op-token", NewID: func() string { n++; return fmt.Sprintf("o%d", n) }}
}

func TestOperator_ProvisionLoginQueue(t *testing.T) {
	d := operatorDeps(t)

	// provision an operator account (the handler; gating is tested separately)
	crec := callRaw(d.handleCreateOperator, http.MethodPost, `{"email":"dana@x.io","name":"Dana","firm":"TS Managed","password":"sup3rsecret"}`)
	if crec.Code != http.StatusOK {
		t.Fatalf("create operator: %d %s", crec.Code, crec.Body.String())
	}
	// weak password / dup rejected
	if r := callRaw(d.handleCreateOperator, http.MethodPost, `{"email":"x@y.io","password":"short"}`); r.Code != http.StatusBadRequest {
		t.Errorf("weak password must be 400, got %d", r.Code)
	}
	if r := callRaw(d.handleCreateOperator, http.MethodPost, `{"email":"dana@x.io","password":"sup3rsecret"}`); r.Code != http.StatusConflict {
		t.Errorf("duplicate operator must be 409, got %d", r.Code)
	}

	// login → token
	lrec := callRaw(d.handleOperatorLogin, http.MethodPost, `{"email":"dana@x.io","password":"sup3rsecret"}`)
	if lrec.Code != http.StatusOK {
		t.Fatalf("login: %d %s", lrec.Code, lrec.Body.String())
	}
	var login struct {
		Token string `json:"token"`
	}
	_ = json.Unmarshal(lrec.Body.Bytes(), &login)
	if login.Token == "" {
		t.Fatal("login returned no token")
	}
	// wrong password → 401
	if r := callRaw(d.handleOperatorLogin, http.MethodPost, `{"email":"dana@x.io","password":"nope"}`); r.Code != http.StatusUnauthorized {
		t.Errorf("bad password must be 401, got %d", r.Code)
	}

	// the operator queue (via operatorAuth) is scoped to dana's tenants only — tenant A, never B
	h := d.operatorAuth(d.handleOperatorQueue)
	req := httptest.NewRequest(http.MethodGet, "/v1/operator/queue", nil)
	req.Header.Set("Authorization", "Bearer "+login.Token)
	rec := httptest.NewRecorder()
	h(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("operator queue: %d %s", rec.Code, rec.Body.String())
	}
	var q struct {
		TenantsServed int              `json:"tenants_served"`
		Items         []map[string]any `json:"items"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &q)
	if q.TenantsServed != 1 {
		t.Fatalf("operator should serve only tenant A, got tenants_served=%d", q.TenantsServed)
	}
	for _, it := range q.Items {
		if it["tenant_id"] != "tA" {
			t.Errorf("ISOLATION: operator queue surfaced a non-assigned tenant: %v", it)
		}
	}

	// no token → 401
	r2 := httptest.NewRequest(http.MethodGet, "/v1/operator/queue", nil)
	w2 := httptest.NewRecorder()
	h(w2, r2)
	if w2.Code != http.StatusUnauthorized {
		t.Errorf("operator queue without a token must be 401, got %d", w2.Code)
	}
}

func callRaw(h http.HandlerFunc, method, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, "/x", strings.NewReader(body))
	rec := httptest.NewRecorder()
	h(rec, req)
	return rec
}
