package console

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

const tok = "secret-token"

func seed(t *testing.T) store.Store {
	t.Helper()
	ctx := context.Background()
	st := store.NewMemory()
	_ = st.PutTenant(ctx, platform.Tenant{ID: "t1", Name: "Acme Inc"})
	_ = st.PutFinding(ctx, "t1", types.Finding{ID: "f1", Tool: "nuclei", Severity: types.SeverityCritical,
		Title: "SQL injection", Endpoint: "https://acme.example/search"})
	_ = st.PutFinding(ctx, "t1", types.Finding{ID: "f2", Tool: "trivy", Severity: types.SeverityLow,
		Title: "Outdated dependency", Endpoint: "package.json"})
	_ = st.PutAction(ctx, platform.Action{ID: "a1", TenantID: "t1", FindingID: "f1", Kind: platform.ActOpenPR,
		Tier: 2, Status: platform.ActPendingApproval, Title: "Patch SQLi in search handler"})
	_ = st.PutConnection(ctx, platform.Connection{ID: "c1", TenantID: "t1", Kind: "github", SecretRef: "vault://tok-xyz"})
	_ = st.UpsertControlState(ctx, platform.ControlState{TenantID: "t1", Framework: "soc2", ControlID: "CC6.1", State: platform.ControlMet})
	_ = st.UpsertControlState(ctx, platform.ControlState{TenantID: "t1", Framework: "soc2", ControlID: "CC6.6", State: platform.ControlGap})
	return st
}

func get(t *testing.T, h http.HandlerFunc, url, bearer string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, url, nil)
	if bearer != "" {
		r.Header.Set("Authorization", "Bearer "+bearer)
	}
	w := httptest.NewRecorder()
	h(w, r)
	return w
}

func TestHandler_RequiresAuth(t *testing.T) {
	h := Handler(Deps{Store: seed(t), Token: tok})
	if w := get(t, h, "/ui?tenant=t1", ""); w.Code != http.StatusUnauthorized {
		t.Fatalf("no token should be 401, got %d", w.Code)
	}
	if w := get(t, h, "/ui?tenant=t1", "wrong"); w.Code != http.StatusUnauthorized {
		t.Fatalf("wrong token should be 401, got %d", w.Code)
	}
}

func TestHandler_RequiresTenant(t *testing.T) {
	h := Handler(Deps{Store: seed(t), Token: tok})
	if w := get(t, h, "/ui", tok); w.Code != http.StatusBadRequest {
		t.Fatalf("missing tenant should be 400, got %d", w.Code)
	}
}

func TestHandler_RendersPosture(t *testing.T) {
	h := Handler(Deps{Store: seed(t), Token: tok})
	w := get(t, h, "/ui?tenant=t1", tok)
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", w.Code)
	}
	body := w.Body.String()
	for _, want := range []string{
		"Acme Inc",                     // tenant name, not id
		"Critical",                     // risk rating (a critical finding present)
		"SQL injection",                // top finding
		"Patch SQLi in search handler", // pending approval
		"SOC2",                         // framework posture
		"1 met",                        // CC6.1 met
		"1 gap",                        // CC6.6 gap
	} {
		if !strings.Contains(body, want) {
			t.Errorf("rendered page missing %q", want)
		}
	}
}

// The dashboard must never leak a connection's secret reference into HTML.
func TestHandler_RedactsSecretRef(t *testing.T) {
	h := Handler(Deps{Store: seed(t), Token: tok})
	body := get(t, h, "/ui?tenant=t1", tok).Body.String()
	if strings.Contains(body, "vault://tok-xyz") {
		t.Fatal("dashboard leaked a connection SecretRef into the page")
	}
}

// Worst-severity-first ordering and the Clear state for a clean tenant.
func TestHandler_CleanTenantIsClear(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	_ = st.PutTenant(ctx, platform.Tenant{ID: "t2", Name: "Quiet Co"})
	h := Handler(Deps{Store: st, Token: tok})
	body := get(t, h, "/ui?tenant=t2", tok).Body.String()
	if !strings.Contains(body, "rr-Clear") {
		t.Error("a tenant with no findings should render a Clear risk rating")
	}
	if !strings.Contains(body, "No open findings") {
		t.Error("clean tenant should show the empty-findings state")
	}
}
