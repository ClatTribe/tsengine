package platformapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/internal/secret"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

// The on-demand door reads Okta's policies through the sealed connection token, stores the findings,
// and returns what the token could NOT read beside the count.
func TestSyncOkta_LiveFetchStoresFindingsAndNamesUnread(t *testing.T) {
	ctx := context.Background()
	okta := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer okta-tok" {
			http.Error(w, "no token", 401)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/api/v1/policies" && r.URL.Query().Get("type") == "PASSWORD":
			w.Write([]byte(`[{"id":"pw","name":"Default","status":"ACTIVE","settings":{"password":{"complexity":{"minLength":6},"lockout":{"maxAttempts":10}}}}]`))
		case r.URL.Path == "/api/v1/policies" && r.URL.Query().Get("type") == "OKTA_SIGN_ON":
			w.Write([]byte(`[]`))
		case r.URL.Path == "/api/v1/policies" && r.URL.Query().Get("type") == "MFA_ENROLL":
			w.Write([]byte(`[]`))
		default:
			http.Error(w, `{"errorCode":"E0000006"}`, 403) // api-tokens, threats, zones: no scope
		}
	}))
	defer okta.Close()

	st := store.NewMemory()
	vault, _ := secret.NewAESGCM(make([]byte, 32))
	ref, _ := vault.Seal("okta-tok")
	_ = st.PutTenant(ctx, platform.Tenant{ID: "t1"})
	_ = st.PutConnection(ctx, platform.Connection{ID: "c-ok", TenantID: "t1", Kind: platform.ConnOkta, Status: platform.ConnActive, Account: "acme", SecretRef: ref})
	n := 0
	d := Deps{Store: st, Vault: vault, OktaOrgURL: okta.URL, NewID: func() string { n++; return fmt.Sprintf("%04d", n) }}

	rec := httptest.NewRecorder()
	d.handleSyncSaaSOkta(rec, httptest.NewRequest(http.MethodPost, "/v1/saas/okta/sync", nil), "t1")
	if rec.Code != http.StatusOK {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	var out struct {
		Count  int               `json:"count"`
		Unread map[string]string `json:"unread"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.Count != 1 {
		t.Errorf("the 6-character password policy should be the one finding, got %d: %s", out.Count, rec.Body.String())
	}
	if len(out.Unread) < 3 || !strings.Contains(out.Unread["api-tokens"], "403") {
		t.Errorf("the endpoints the token could not read must be NAMED in the response: %v", out.Unread)
	}
	stored, _ := st.ListFindings(ctx, "t1", store.FindingFilter{})
	if len(stored) != 1 || stored[0].RuleID != "sspm::okta::password-min-length-short" {
		t.Errorf("stored: %+v", stored)
	}

	// No org URL on the deployment → 503 that says so; no Okta connection → 400.
	rec2 := httptest.NewRecorder()
	Deps{Store: st, Vault: vault}.handleSyncSaaSOkta(rec2, httptest.NewRequest(http.MethodPost, "/v1/saas/okta/sync", nil), "t1")
	if rec2.Code != http.StatusServiceUnavailable || !strings.Contains(rec2.Body.String(), "OKTA_ORG_URL") {
		t.Errorf("missing org URL: %d %s", rec2.Code, rec2.Body.String())
	}
	st2 := store.NewMemory()
	_ = st2.PutTenant(ctx, platform.Tenant{ID: "t2"})
	rec3 := httptest.NewRecorder()
	Deps{Store: st2, Vault: vault, OktaOrgURL: okta.URL}.handleSyncSaaSOkta(rec3, httptest.NewRequest(http.MethodPost, "/v1/saas/okta/sync", nil), "t2")
	if rec3.Code != http.StatusBadRequest {
		t.Errorf("no connection: %d %s", rec3.Code, rec3.Body.String())
	}
}
