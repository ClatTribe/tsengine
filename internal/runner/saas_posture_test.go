package runner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/internal/connector"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

// A monitoring pass auto-runs the live GitHub-org SSPM sync via the onboarded token: a tenant with
// a GitHub connection gets posture findings stored with no manual trigger and no extra credential.
func TestRescanTenant_AutoSyncsGitHubPosture(t *testing.T) {
	ctx := context.Background()
	// fake GitHub API: a misconfigured org so AssessGitHubOrg produces findings.
	gh := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/hooks") {
			w.Write([]byte(`[]`))
			return
		}
		w.Write([]byte(`{"login":"acme","two_factor_requirement_enabled":false,
			"default_repository_permission":"write","members_can_create_public_repositories":true,
			"security_and_analysis":{"secret_scanning":{"status":"disabled"},
			"secret_scanning_push_protection":{"status":"disabled"}}}`))
	}))
	defer gh.Close()

	st := store.NewMemory()
	_ = st.PutTenant(ctx, platform.Tenant{ID: "t1"})
	_ = st.PutConnection(ctx, platform.Connection{ID: "c-gh", TenantID: "t1", Kind: platform.ConnGitHub,
		Status: platform.ConnActive, Account: "acme", SecretRef: "vault:tok"})

	n := 0
	svc := &Service{
		Store: st, Connectors: connector.NewRegistry(), Tokens: fakeTokens{},
		Scanner: &togglingScanner{Open: false}, NewID: func() string { n++; return itoa(n) },
		GitHubAPIBase: gh.URL,
	}
	if _, err := svc.RescanTenant(ctx, "t1"); err != nil {
		t.Fatal(err)
	}
	got, _ := st.ListFindings(ctx, "t1", store.FindingFilter{})
	if len(got) == 0 {
		t.Fatal("a monitoring pass should auto-store GitHub SSPM findings")
	}
	if got[0].Tool != "sspm" {
		t.Errorf("auto-synced findings should be tool=sspm, got %q", got[0].Tool)
	}
}

// No GitHub connection → the SSPM sync is a clean no-op (the pass still succeeds, stores nothing).
func TestRescanTenant_NoGitHubNoPosture(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	_ = st.PutTenant(ctx, platform.Tenant{ID: "t1"})
	svc := &Service{
		Store: st, Connectors: connector.NewRegistry(), Tokens: fakeTokens{},
		Scanner: &togglingScanner{Open: false}, NewID: func() string { return "x" },
	}
	if _, err := svc.RescanTenant(ctx, "t1"); err != nil {
		t.Fatal(err)
	}
	if got, _ := st.ListFindings(ctx, "t1", store.FindingFilter{}); len(got) != 0 {
		t.Errorf("no GitHub connection → no posture findings, got %d", len(got))
	}
}
