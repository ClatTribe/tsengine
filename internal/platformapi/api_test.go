package platformapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/internal/connector"
	"github.com/ClatTribe/tsengine/internal/runner"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// --- fakes (mirror the runner test fakes; one push trigger) ---

type fakeConn struct{}

func (fakeConn) Kind() string { return platform.ConnGitHub }
func (fakeConn) OAuthURL(state, redirect string) string {
	return "https://gh/login/oauth/authorize?state=" + state + "&redirect_uri=" + redirect
}
func (fakeConn) Exchange(context.Context, string, string) (platform.Connection, error) {
	return platform.Connection{}, nil
}
func (fakeConn) Discover(_ context.Context, c platform.Connection, _ string) ([]platform.Asset, error) {
	return []platform.Asset{{ID: "a1", TenantID: c.TenantID, ConnectionID: c.ID, Type: "repository", Target: "https://github.com/acme/web"}}, nil
}
func (fakeConn) Watch(_ context.Context, c platform.Connection, _ []byte) ([]connector.Trigger, error) {
	return []connector.Trigger{{TenantID: c.TenantID, ConnectionID: c.ID, AssetTarget: "https://github.com/acme/web", Kind: platform.TriggerPush}}, nil
}
func (fakeConn) Apply(context.Context, platform.Connection, string, platform.Action) error {
	return nil
}

type fakeTokens struct{}

func (fakeTokens) Resolve(context.Context, platform.Connection) (string, error) { return "tok", nil }

type fakeScanner struct{}

func (fakeScanner) Scan(_ context.Context, a platform.Asset) ([]types.Finding, error) {
	return []types.Finding{{ID: "f1", Severity: types.SeverityHigh, Title: "SQLi in " + a.Target}}, nil
}

func setup(t *testing.T) (http.Handler, store.Store) {
	t.Helper()
	st := store.NewMemory()
	ctx := context.Background()
	// seed a tenant + an active github connection + the asset it will rescan
	_ = st.PutTenant(ctx, platform.Tenant{ID: "t1", Name: "Acme"})
	_ = st.PutConnection(ctx, platform.Connection{ID: "c1", TenantID: "t1", Kind: platform.ConnGitHub, Status: platform.ConnActive, SecretRef: "vault:SECRET"})
	_ = st.PutAsset(ctx, platform.Asset{ID: "a1", TenantID: "t1", ConnectionID: "c1", Type: "repository", Target: "https://github.com/acme/web"})

	svc := &runner.Service{Store: st, Connectors: connector.NewRegistry(fakeConn{}), Tokens: fakeTokens{}, Scanner: fakeScanner{}}
	h := NewHandler(Deps{Store: st, Connectors: connector.NewRegistry(fakeConn{}), Runner: svc, Token: "platform-tok"})
	return h, st
}

func do(h http.Handler, method, path, tenant string, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer platform-tok")
	if tenant != "" {
		req.Header.Set("X-Tenant-ID", tenant)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// do2 issues a request with NO auth headers — for public endpoints (the Trust Center).
func do2(h http.Handler, method, path string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// The quarantine endpoint (WRD-4) flips one connection's status active↔quarantined and
// never leaks the sealed secret ref.
func TestQuarantineConnection(t *testing.T) {
	h, st := setup(t)
	ctx := context.Background()

	rec := do(h, "POST", "/v1/connections/c1/quarantine", "t1", `{"quarantined":true}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("quarantine: want 200, got %d (%s)", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "vault:") || strings.Contains(rec.Body.String(), "SECRET") {
		t.Errorf("quarantine response leaked the secret ref: %s", rec.Body.String())
	}
	if cs, _ := st.ListConnections(ctx, "t1"); cs[0].Status != platform.ConnQuarantined {
		t.Errorf("connection should be quarantined, got %q", cs[0].Status)
	}

	if rec := do(h, "POST", "/v1/connections/c1/quarantine", "t1", `{"quarantined":false}`); rec.Code != http.StatusOK {
		t.Fatalf("restore: want 200, got %d", rec.Code)
	}
	if cs, _ := st.ListConnections(ctx, "t1"); cs[0].Status != platform.ConnActive {
		t.Errorf("restore should set active, got %q", cs[0].Status)
	}

	if rec := do(h, "POST", "/v1/connections/ghost/quarantine", "t1", `{"quarantined":true}`); rec.Code != http.StatusNotFound {
		t.Errorf("unknown connection: want 404, got %d", rec.Code)
	}
}

// The kill-switch endpoint toggles Tenant.AgentsHalted and the tenant read reflects it.
func TestKillSwitchToggle(t *testing.T) {
	h, st := setup(t)
	ctx := context.Background()

	if rec := do(h, "POST", "/v1/killswitch", "t1", `{"halted":true}`); rec.Code != http.StatusOK {
		t.Fatalf("engage kill-switch: want 200, got %d (%s)", rec.Code, rec.Body.String())
	}
	if tn, _ := st.GetTenant(ctx, "t1"); !tn.AgentsHalted {
		t.Fatal("tenant should be halted after engage")
	}
	if g := do(h, "GET", "/v1/tenant", "t1", ""); !strings.Contains(g.Body.String(), `"agents_halted":true`) {
		t.Fatalf("GET /v1/tenant should report halted: %s", g.Body.String())
	}

	if rec := do(h, "POST", "/v1/killswitch", "t1", `{"halted":false}`); rec.Code != http.StatusOK {
		t.Fatalf("disengage kill-switch: want 200, got %d", rec.Code)
	}
	if tn, _ := st.GetTenant(ctx, "t1"); tn.AgentsHalted {
		t.Fatal("tenant should be resumed after disengage")
	}
}

func TestWebhookTriggersScanThenFindingsQueryable(t *testing.T) {
	h, _ := setup(t)

	// 1) a push webhook → the asset is re-scanned
	rec := do(h, "POST", "/v1/webhooks/github", "t1", `{"repository":{"html_url":"https://github.com/acme/web"}}`)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("webhook: code %d body %s", rec.Code, rec.Body.String())
	}
	var wr struct {
		EngagementsStarted int `json:"engagements_started"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &wr)
	if wr.EngagementsStarted != 1 {
		t.Fatalf("want 1 engagement, got %d", wr.EngagementsStarted)
	}

	// 2) the grounded finding is now queryable for the tenant
	rec = do(h, "GET", "/v1/findings", "t1", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("findings: code %d", rec.Code)
	}
	var fs []types.Finding
	_ = json.Unmarshal(rec.Body.Bytes(), &fs)
	if len(fs) != 1 || fs[0].ID != "f1" {
		t.Fatalf("want the scan finding, got %+v", fs)
	}
}

func TestAuthAndTenantScoping(t *testing.T) {
	h, _ := setup(t)

	// no token → 401
	req := httptest.NewRequest("GET", "/v1/findings", nil)
	req.Header.Set("X-Tenant-ID", "t1")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("missing token should be 401, got %d", rec.Code)
	}

	// token but no tenant → 400
	rec = do(h, "GET", "/v1/findings", "", "")
	if rec.Code != http.StatusBadRequest {
		t.Errorf("missing tenant should be 400, got %d", rec.Code)
	}

	// a different tenant sees none of t1's data (isolation through the API)
	rec = do(h, "POST", "/v1/webhooks/github", "t1", `{"repository":{"html_url":"https://github.com/acme/web"}}`)
	_ = rec
	rec = do(h, "GET", "/v1/findings", "t2", "")
	var fs []types.Finding
	_ = json.Unmarshal(rec.Body.Bytes(), &fs)
	if len(fs) != 0 {
		t.Errorf("ISOLATION: t2 must see no findings via the API, got %d", len(fs))
	}
}

func TestAssets_ListsMonitored(t *testing.T) {
	h, _ := setup(t)
	rec := do(h, "GET", "/v1/assets", "t1", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /v1/assets: want 200, got %d", rec.Code)
	}
	var assets []platform.Asset
	if err := json.Unmarshal(rec.Body.Bytes(), &assets); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(assets) != 1 || assets[0].Target != "https://github.com/acme/web" {
		t.Fatalf("want the seeded repo asset, got %+v", assets)
	}
	// isolation: a different tenant sees none of t1's assets
	rec = do(h, "GET", "/v1/assets", "t2", "")
	var other []platform.Asset
	_ = json.Unmarshal(rec.Body.Bytes(), &other)
	if len(other) != 0 {
		t.Errorf("ISOLATION: t2 must see no assets, got %d", len(other))
	}
}

func TestConnectionsRedactSecretRef(t *testing.T) {
	h, _ := setup(t)
	rec := do(h, "GET", "/v1/connections", "t1", "")
	if strings.Contains(rec.Body.String(), "SECRET") || strings.Contains(rec.Body.String(), "secret_ref") && strings.Contains(rec.Body.String(), "vault") {
		t.Errorf("connections endpoint leaked the secret ref: %s", rec.Body.String())
	}
}

func TestGetTenant_ReturnsOwnOrg(t *testing.T) {
	h, _ := setup(t)
	rec := do(h, "GET", "/v1/tenant", "t1", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /v1/tenant: want 200, got %d", rec.Code)
	}
	var ten platform.Tenant
	if err := json.Unmarshal(rec.Body.Bytes(), &ten); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if ten.ID != "t1" || ten.Name != "Acme" {
		t.Fatalf("want the t1/Acme tenant, got %+v", ten)
	}
}

func TestTrustCenter_TokenGatedAndSafe(t *testing.T) {
	h, d := setup(t)

	// wrong / missing token → 404 (no enumeration by tenant id)
	if rec := do2(h, "GET", "/v1/trust/t1?token=wrong"); rec.Code != http.StatusNotFound {
		t.Fatalf("bad token must 404, got %d", rec.Code)
	}
	if rec := do2(h, "GET", "/v1/trust/t1"); rec.Code != http.StatusNotFound {
		t.Fatalf("missing token must 404, got %d", rec.Code)
	}

	// the owner can fetch their own share token (authed)
	rec := do(h, "GET", "/v1/trust-link", "t1", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("trust-link: want 200, got %d", rec.Code)
	}
	var link struct{ Token string }
	_ = json.Unmarshal(rec.Body.Bytes(), &link)
	if link.Token == "" {
		t.Fatal("trust-link returned no token")
	}

	// the correct token → 200 with safe aggregates and NO leaked findings/endpoints
	rec = do2(h, "GET", "/v1/trust/t1?token="+link.Token)
	if rec.Code != http.StatusOK {
		t.Fatalf("valid token: want 200, got %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "Acme") {
		t.Errorf("trust view should carry the org name, got %s", body)
	}
	for _, leak := range []string{"endpoint", "rule_id", "finding", "github.com/acme/web"} {
		if strings.Contains(body, leak) {
			t.Errorf("PRIVACY: trust view leaked %q: %s", leak, body)
		}
	}
	_ = d
}

func TestCreateTenant_Provisions(t *testing.T) {
	st := store.NewMemory()
	h := NewHandler(Deps{Store: st, Connectors: connector.NewRegistry(), Token: "platform-tok"})

	// token only (no tenant header) → provisions a tenant
	req := httptest.NewRequest("POST", "/v1/tenants", strings.NewReader(`{"name":"Acme Corp","plan":"pro"}`))
	req.Header.Set("Authorization", "Bearer platform-tok")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create tenant: code %d body %s", rec.Code, rec.Body.String())
	}
	var tn platform.Tenant
	_ = json.Unmarshal(rec.Body.Bytes(), &tn)
	if tn.ID == "" || tn.Name != "Acme Corp" {
		t.Fatalf("tenant wrong: %+v", tn)
	}
	// it's persisted + retrievable
	got, err := st.GetTenant(context.Background(), tn.ID)
	if err != nil || got.Name != "Acme Corp" {
		t.Errorf("tenant not persisted: %+v %v", got, err)
	}

	// missing name → 400; missing token → 401
	bad := do(h, "POST", "/v1/tenants", "", `{}`)
	if bad.Code != http.StatusBadRequest {
		t.Errorf("nameless tenant should be 400, got %d", bad.Code)
	}
	noauth := httptest.NewRequest("POST", "/v1/tenants", strings.NewReader(`{"name":"x"}`))
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, noauth)
	if rec2.Code != http.StatusUnauthorized {
		t.Errorf("no token should be 401, got %d", rec2.Code)
	}
}

func TestHealthz(t *testing.T) {
	h, _ := setup(t)
	req := httptest.NewRequest("GET", "/healthz", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("healthz code %d", rec.Code)
	}
}

// verifyConn is a fakeConn that also implements connector.WebhookVerifier (accepts when
// header X-Sig == secret), to exercise the webhook-verification gate.
type verifyConn struct{ fakeConn }

func (verifyConn) VerifyWebhook(h http.Header, _ []byte, secret string) error {
	if h.Get("X-Sig") == secret {
		return nil
	}
	return errTestBadSig
}

var errTestBadSig = &testErr{"bad sig"}

type testErr struct{ s string }

func (e *testErr) Error() string { return e.s }

func webhookReq(secret string) *http.Request {
	req := httptest.NewRequest("POST", "/v1/webhooks/github", strings.NewReader(`{"repository":{"html_url":"https://github.com/acme/web"}}`))
	req.Header.Set("Authorization", "Bearer platform-tok")
	req.Header.Set("X-Tenant-ID", "t1")
	if secret != "" {
		req.Header.Set("X-Sig", secret)
	}
	return req
}

func TestWebhook_VerifiesSignature(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	_ = st.PutTenant(ctx, platform.Tenant{ID: "t1"})
	_ = st.PutConnection(ctx, platform.Connection{ID: "c1", TenantID: "t1", Kind: platform.ConnGitHub, Status: platform.ConnActive, SecretRef: "v:S"})
	_ = st.PutAsset(ctx, platform.Asset{ID: "a1", TenantID: "t1", ConnectionID: "c1", Type: "repository", Target: "https://github.com/acme/web"})
	reg := connector.NewRegistry(verifyConn{})
	svc := &runner.Service{Store: st, Connectors: reg, Tokens: fakeTokens{}, Scanner: fakeScanner{}}
	h := NewHandler(Deps{Store: st, Connectors: reg, Runner: svc, Token: "platform-tok", WebhookSecret: "shh"})

	// no/!valid signature → 401, no re-scan
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, webhookReq(""))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("an unsigned webhook must be rejected, got %d", rec.Code)
	}
	if fs, _ := st.ListFindings(ctx, "t1", store.FindingFilter{}); len(fs) != 0 {
		t.Fatal("a rejected webhook must NOT trigger a scan")
	}
	// valid signature → 202 + scan runs
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, webhookReq("shh"))
	if rec.Code != http.StatusAccepted {
		t.Fatalf("a verified webhook should be accepted, got %d: %s", rec.Code, rec.Body.String())
	}
	if fs, _ := st.ListFindings(ctx, "t1", store.FindingFilter{}); len(fs) == 0 {
		t.Error("a verified webhook should trigger the re-scan")
	}
}

func TestRespond_NilSliceSerializesAsEmptyArray(t *testing.T) {
	// A nil slice must serialize as [] not null — a null crashes a frontend .map/.filter
	// (the Go nil-slice → JSON-null footgun). Every list endpoint goes through respond().
	rec := httptest.NewRecorder()
	var nilSlice []platform.Action
	respond(rec, nilSlice, nil)
	if got := strings.TrimSpace(rec.Body.String()); got != "[]" {
		t.Errorf("a nil slice must serialize as [], got %q", got)
	}
	// A non-empty slice is unchanged.
	rec2 := httptest.NewRecorder()
	respond(rec2, []platform.Action{{ID: "a1"}}, nil)
	if !strings.Contains(rec2.Body.String(), "a1") {
		t.Errorf("a populated slice must serialize its elements, got %q", rec2.Body.String())
	}
	// A non-slice (object) passes through untouched.
	rec3 := httptest.NewRecorder()
	respond(rec3, map[string]int{"n": 1}, nil)
	if !strings.Contains(rec3.Body.String(), "\"n\":1") {
		t.Errorf("a map must serialize untouched, got %q", rec3.Body.String())
	}
}
