package console

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/internal/hitl"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/ledger"
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

// deps builds a console wired to a real (non-applying) desk for approval tests.
func deps(t *testing.T, st store.Store) Deps {
	t.Helper()
	desk := &hitl.Desk{Store: st, Apply: applyNoop{}, Recorder: ledger.NewRecorder()}
	return Deps{Store: st, Token: tok, Desk: desk}
}

// applyNoop satisfies the desk's Applier without doing anything (tier-2 approve path).
type applyNoop struct{}

func (applyNoop) Apply(_ context.Context, _ platform.Action) error { return nil }

// getBearer issues a GET with the bearer header (the programmatic read path).
func getBearer(t *testing.T, h http.Handler, target string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, target, nil)
	r.Header.Set("Authorization", "Bearer "+tok)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestDashboard_RendersPosture(t *testing.T) {
	h := Handler(deps(t, seed(t)))
	w := getBearer(t, h, "/ui?tenant=t1")
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
		`action="/ui/approvals/a1"`,    // the approve/reject forms are wired
	} {
		if !strings.Contains(body, want) {
			t.Errorf("rendered page missing %q", want)
		}
	}
}

// Unauthenticated GET shows the login page (200), never the dashboard.
func TestDashboard_UnauthShowsLogin(t *testing.T) {
	h := Handler(deps(t, seed(t)))
	r := httptest.NewRequest(http.MethodGet, "/ui?tenant=t1", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("login page should be 200, got %d", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, "Sign in") || strings.Contains(body, "SQL injection") {
		t.Fatal("unauthenticated GET must render the login page, not the dashboard")
	}
}

// Signed-in but no tenant → tenant picker.
func TestDashboard_NoTenantShowsPicker(t *testing.T) {
	h := Handler(deps(t, seed(t)))
	body := getBearer(t, h, "/ui").Body.String()
	if !strings.Contains(body, "Choose a tenant") || !strings.Contains(body, "Acme Inc") {
		t.Fatal("authenticated GET without tenant should list tenants")
	}
}

// Login with the right token sets the session cookie and redirects.
func TestLogin_SetsCookieAndRedirects(t *testing.T) {
	h := Handler(deps(t, seed(t)))
	form := url.Values{"token": {tok}, "tenant": {"t1"}, "operator": {"Riya"}}
	r := httptest.NewRequest(http.MethodPost, "/ui/login", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("login should redirect (303), got %d", w.Code)
	}
	var session, op bool
	for _, c := range w.Result().Cookies() {
		if c.Name == sessionCookie && c.Value == tok && c.HttpOnly {
			session = true
		}
		if c.Name == operatorCookie && c.Value == "Riya" {
			op = true
		}
	}
	if !session {
		t.Error("login should set an httpOnly session cookie")
	}
	if !op {
		t.Error("login should remember the operator name")
	}
}

func TestLogin_WrongTokenRejected(t *testing.T) {
	h := Handler(deps(t, seed(t)))
	form := url.Values{"token": {"nope"}}
	r := httptest.NewRequest(http.MethodPost, "/ui/login", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("wrong token should be 401, got %d", w.Code)
	}
	if len(w.Result().Cookies()) != 0 {
		t.Error("a failed login must not set a session cookie")
	}
}

// A cookie session can drive the dashboard (the browser path).
func TestDashboard_CookieSessionWorks(t *testing.T) {
	h := Handler(deps(t, seed(t)))
	r := httptest.NewRequest(http.MethodGet, "/ui?tenant=t1", nil)
	r.AddCookie(&http.Cookie{Name: sessionCookie, Value: tok})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "SQL injection") {
		t.Fatalf("a valid session cookie should render the dashboard, got %d", w.Code)
	}
}

// Approving from the console drives the gated desk: the action leaves the pending queue.
func TestDecide_ApproveThroughDesk(t *testing.T) {
	st := seed(t)
	h := Handler(deps(t, st))
	form := url.Values{"tenant": {"t1"}, "decision": {"approve"}}
	r := httptest.NewRequest(http.MethodPost, "/ui/approvals/a1", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.AddCookie(&http.Cookie{Name: sessionCookie, Value: tok})
	r.AddCookie(&http.Cookie{Name: operatorCookie, Value: "Riya"})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("decide should redirect, got %d", w.Code)
	}
	pend, _ := st.PendingApprovals(context.Background(), "t1")
	if len(pend) != 0 {
		t.Fatalf("approved action should leave the pending queue, %d still pending", len(pend))
	}
	act, _ := st.GetAction(context.Background(), "t1", "a1")
	if act.Approver != "Riya" {
		t.Errorf("the operator name should be recorded as approver, got %q", act.Approver)
	}
}

// Approving without a session must NOT reach the desk.
func TestDecide_RequiresAuth(t *testing.T) {
	st := seed(t)
	h := Handler(deps(t, st))
	form := url.Values{"tenant": {"t1"}, "decision": {"approve"}}
	r := httptest.NewRequest(http.MethodPost, "/ui/approvals/a1", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code == http.StatusSeeOther {
		t.Fatal("unauthenticated decide must not succeed")
	}
	pend, _ := st.PendingApprovals(context.Background(), "t1")
	if len(pend) != 1 {
		t.Fatal("unauthenticated decide must not touch the pending queue")
	}
}

// The dashboard must never leak a connection's secret reference into HTML.
func TestDashboard_RedactsSecretRef(t *testing.T) {
	h := Handler(deps(t, seed(t)))
	body := getBearer(t, h, "/ui?tenant=t1").Body.String()
	if strings.Contains(body, "vault://tok-xyz") {
		t.Fatal("dashboard leaked a connection SecretRef into the page")
	}
}

// A clean tenant renders Clear with the empty-findings state.
func TestDashboard_CleanTenantIsClear(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	_ = st.PutTenant(ctx, platform.Tenant{ID: "t2", Name: "Quiet Co"})
	h := Handler(deps(t, st))
	body := getBearer(t, h, "/ui?tenant=t2").Body.String()
	if !strings.Contains(body, "rr-Clear") {
		t.Error("a tenant with no findings should render a Clear risk rating")
	}
	if !strings.Contains(body, "No open findings") {
		t.Error("clean tenant should show the empty-findings state")
	}
}
