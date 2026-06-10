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

func (fakeConn) Kind() string                   { return platform.ConnGitHub }
func (fakeConn) OAuthURL(string, string) string { return "" }
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

func TestConnectionsRedactSecretRef(t *testing.T) {
	h, _ := setup(t)
	rec := do(h, "GET", "/v1/connections", "t1", "")
	if strings.Contains(rec.Body.String(), "SECRET") || strings.Contains(rec.Body.String(), "secret_ref") && strings.Contains(rec.Body.String(), "vault") {
		t.Errorf("connections endpoint leaked the secret ref: %s", rec.Body.String())
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
