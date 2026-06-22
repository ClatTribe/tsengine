package platformapi

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/internal/secret"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

// a minimal fake GitHub org API returning a misconfigured org (so AssessGitHubOrg flags it).
func fakeGitHubAPI(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/hooks") {
			w.Write([]byte(`[]`))
			return
		}
		w.Write([]byte(`{"login":"acme","two_factor_requirement_enabled":false,
			"default_repository_permission":"write","members_can_create_public_repositories":true,
			"security_and_analysis":{"secret_scanning":{"status":"disabled"},
			"secret_scanning_push_protection":{"status":"disabled"}}}`))
	}))
}

func TestSyncGitHub_LiveFetchStoresFindings(t *testing.T) {
	ctx := context.Background()
	gh := fakeGitHubAPI(t)
	defer gh.Close()

	st := store.NewMemory()
	vault, _ := secret.NewAESGCM(make([]byte, 32))
	ref, _ := vault.Seal("tok-123")
	_ = st.PutConnection(ctx, platform.Connection{ID: "c-gh", TenantID: "t1", Kind: platform.ConnGitHub,
		Status: platform.ConnActive, Account: "acme", SecretRef: ref})

	n := 0
	d := Deps{Store: st, Vault: vault, GitHubAPIBase: gh.URL, NewID: func() string { n++; return fmt.Sprintf("%04d", n) }}

	req := httptest.NewRequest(http.MethodPost, "/v1/saas/github_org/sync", nil)
	rec := httptest.NewRecorder()
	d.handleSyncSaaSGitHub(rec, req, "t1")
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"source":"live"`) {
		t.Errorf("response should mark source:live, got %s", rec.Body.String())
	}
	stored, _ := st.ListFindings(ctx, "t1", store.FindingFilter{})
	if len(stored) == 0 {
		t.Error("live sync of a misconfigured org should store SSPM findings")
	}
	if len(stored) > 0 && stored[0].Tool != "sspm" {
		t.Errorf("findings should be tool=sspm, got %q", stored[0].Tool)
	}
}

func TestSyncGitHub_NoConnectionIs400(t *testing.T) {
	st := store.NewMemory()
	vault, _ := secret.NewAESGCM(make([]byte, 32))
	d := Deps{Store: st, Vault: vault, NewID: func() string { return "x" }}
	req := httptest.NewRequest(http.MethodPost, "/v1/saas/github_org/sync", nil)
	rec := httptest.NewRecorder()
	d.handleSyncSaaSGitHub(rec, req, "t1")
	if rec.Code != http.StatusBadRequest {
		t.Errorf("a tenant with no GitHub connection must be 400, got %d", rec.Code)
	}
}
