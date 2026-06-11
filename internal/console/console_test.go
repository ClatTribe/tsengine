package console

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/ClatTribe/tsengine/internal/connector"
	"github.com/ClatTribe/tsengine/internal/grc"
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
	_ = st.PutIncident(ctx, platform.Incident{ID: "i1", TenantID: "t1", Title: "Admin without MFA", RuleID: "operate::admin-without-mfa", Severity: "critical", Status: platform.IncidentOpen})
	_ = st.PutAsset(ctx, platform.Asset{ID: "as1", TenantID: "t1", Type: "repository", Target: "github.com/acme/web"})
	_ = st.PutEngagement(ctx, platform.Engagement{ID: "e1", TenantID: "t1", AssetID: "as1", CompletedAt: time.Date(2026, 6, 1, 9, 30, 0, 0, time.UTC)})
	_ = st.ReplaceThirdPartyApps(ctx, "t1", "okta", []platform.ThirdPartyApp{
		{TenantID: "t1", Provider: "okta", AppID: "Risky Provisioner", Scopes: []string{"okta.users.manage"}, Users: 3, AdminScope: true, Verified: false},
	})
	_ = st.UpsertControlState(ctx, platform.ControlState{TenantID: "t1", Framework: "soc2", ControlID: "CC6.1", State: platform.ControlMet})
	_ = st.UpsertControlState(ctx, platform.ControlState{TenantID: "t1", Framework: "soc2", ControlID: "CC6.6", State: platform.ControlGap})
	return st
}

// deps builds a console wired to a real (non-applying) desk, the GRC reporter, and a
// connector registry (GitHub) for onboarding.
func deps(t *testing.T, st store.Store) Deps {
	t.Helper()
	desk := &hitl.Desk{Store: st, Apply: applyNoop{}, Recorder: ledger.NewRecorder()}
	return Deps{
		Store: st, Token: tok, Desk: desk, Report: &grc.GRC{Store: st},
		Connectors: connector.NewRegistry(connector.NewGitHub("client-123", "secret")),
		PublicURL:  "https://app.example",
		Rescan:     &fakeRescanner{},
	}
}

// fakeRescanner records that a rescan was requested.
type fakeRescanner struct{ calls []string }

func (f *fakeRescanner) RescanTenant(_ context.Context, tenantID string) (int, error) {
	f.calls = append(f.calls, tenantID)
	return 1, nil
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
		"New since last scan",          // the continuous-monitoring incidents section
		"Admin without MFA",            // the open incident renders
		"Monitored assets",             // the asset-inventory section
		"github.com/acme/web",          // the monitored asset
		"2026-06-01 09:30 UTC",         // its last-scanned time
		"Scan now",                     // the manual rescan button
		"Third-party apps with access", // the OAuth app inventory section
		"Risky Provisioner",            // the inventoried app
		"admin / directory",            // its admin-scope badge
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

// The posture cards link into the per-framework drill-down when a reporter is wired.
func TestDashboard_PostureCardsLink(t *testing.T) {
	h := Handler(deps(t, seed(t)))
	body := getBearer(t, h, "/ui?tenant=t1").Body.String()
	if !strings.Contains(body, `href="/ui/compliance/soc2?tenant=t1"`) {
		t.Error("SOC2 posture card should link to the compliance drill-down")
	}
}

// The compliance page resolves gaps to their citing findings.
func TestCompliance_RendersGapsAndEvidence(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	_ = st.PutTenant(ctx, platform.Tenant{ID: "t1", Name: "Acme Inc"})
	crit := types.Finding{ID: "f-001", Title: "SQL injection", Severity: types.SeverityCritical,
		Compliance: &types.Compliance{SOC2: []string{"CC6.1"}}}
	_ = st.PutFinding(ctx, "t1", crit)
	g := &grc.GRC{Store: st}
	if err := g.Apply(ctx, "t1", crit); err != nil { // CC6.1 → gap, cites f-001
		t.Fatal(err)
	}
	h := Handler(Deps{Store: st, Token: tok, Report: g})
	body := getBearer(t, h, "/ui/compliance/soc2?tenant=t1").Body.String()
	for _, want := range []string{
		"SOC 2 Compliance", "CC6.1", "GAP", "SQL injection", "critical", "← Dashboard",
		"GET /v1/compliance/soc2/report",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("compliance page missing %q", want)
		}
	}
}

// The compliance page is gated behind auth like everything else.
func TestCompliance_RequiresAuth(t *testing.T) {
	h := Handler(deps(t, seed(t)))
	r := httptest.NewRequest(http.MethodGet, "/ui/compliance/soc2?tenant=t1", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if strings.Contains(w.Body.String(), "GAP") {
		t.Fatal("unauthenticated compliance request must not render the report")
	}
}

// The connect page lists available connectors with a Connect button.
func TestConnectPage_ListsConnectors(t *testing.T) {
	h := Handler(deps(t, seed(t)))
	body := getBearer(t, h, "/ui/connect?tenant=t1").Body.String()
	for _, want := range []string{"Connect a system", "GitHub", `href="/ui/connect/github?tenant=t1"`, "← Dashboard"} {
		if !strings.Contains(body, want) {
			t.Errorf("connect page missing %q", want)
		}
	}
}

// Hitting connect kicks off the provider OAuth consent with the tenant as CSRF state.
func TestConnect_RedirectsToProvider(t *testing.T) {
	h := Handler(deps(t, seed(t)))
	w := getBearer(t, h, "/ui/connect/github?tenant=t1")
	if w.Code != http.StatusSeeOther {
		t.Fatalf("connect should redirect to the provider, got %d", w.Code)
	}
	loc := w.Header().Get("Location")
	if !strings.Contains(loc, "github.com/login/oauth/authorize") {
		t.Errorf("redirect should target GitHub OAuth, got %q", loc)
	}
	if !strings.Contains(loc, "state=t1") {
		t.Errorf("OAuth state should carry the tenant id, got %q", loc)
	}
	if !strings.Contains(loc, "redirect_uri=https%3A%2F%2Fapp.example%2Fv1%2Fconnect%2Fgithub%2Fcallback") {
		t.Errorf("redirect_uri should point at the callback, got %q", loc)
	}
}

// Onboarding is auth-gated like the rest of the console.
func TestConnect_RequiresAuth(t *testing.T) {
	h := Handler(deps(t, seed(t)))
	r := httptest.NewRequest(http.MethodGet, "/ui/connect/github?tenant=t1", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code == http.StatusSeeOther && strings.Contains(w.Header().Get("Location"), "github.com") {
		t.Fatal("unauthenticated connect must not start the OAuth flow")
	}
}

// "Scan now" triggers a tenant rescan through the wired Rescanner.
func TestRescan_TriggersTenantScan(t *testing.T) {
	rs := &fakeRescanner{}
	h := Handler(Deps{Store: seed(t), Token: tok, Rescan: rs})
	form := url.Values{"tenant": {"t1"}}
	r := httptest.NewRequest(http.MethodPost, "/ui/rescan", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.AddCookie(&http.Cookie{Name: sessionCookie, Value: tok})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("rescan should redirect, got %d", w.Code)
	}
	if len(rs.calls) != 1 || rs.calls[0] != "t1" {
		t.Errorf("rescan should call RescanTenant(t1) once, got %v", rs.calls)
	}
}

// Rescan is auth-gated like the rest of the console.
func TestRescan_RequiresAuth(t *testing.T) {
	rs := &fakeRescanner{}
	h := Handler(Deps{Store: seed(t), Token: tok, Rescan: rs})
	form := url.Values{"tenant": {"t1"}}
	r := httptest.NewRequest(http.MethodPost, "/ui/rescan", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if len(rs.calls) != 0 {
		t.Error("unauthenticated rescan must not run a scan")
	}
}

// The dashboard surfaces the Connect link when a connector source is wired.
func TestDashboard_ShowsConnectLink(t *testing.T) {
	h := Handler(deps(t, seed(t)))
	body := getBearer(t, h, "/ui?tenant=t1").Body.String()
	if !strings.Contains(body, `href="/ui/connect?tenant=t1"`) {
		t.Error("dashboard should offer a Connect a system link")
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
