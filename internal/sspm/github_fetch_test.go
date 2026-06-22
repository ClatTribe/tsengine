package sspm

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// fakeGitHub serves the org endpoints FetchGitHubOrg reads. `misconfigured` flips every org-config
// field to its insecure value so AssessGitHubOrg has something to flag.
func fakeGitHub(t *testing.T, misconfigured bool) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer tok-123" {
			t.Errorf("missing/wrong bearer token: %q", got)
		}
		switch {
		case strings.HasSuffix(r.URL.Path, "/hooks"):
			w.Write([]byte(`[]`))
		case strings.HasPrefix(r.URL.Path, "/orgs/"):
			if misconfigured {
				w.Write([]byte(`{"login":"acme","two_factor_requirement_enabled":false,
					"default_repository_permission":"write","members_can_create_public_repositories":true,
					"security_and_analysis":{"secret_scanning":{"status":"disabled"},
					"secret_scanning_push_protection":{"status":"disabled"}}}`))
			} else {
				w.Write([]byte(`{"login":"acme","two_factor_requirement_enabled":true,
					"default_repository_permission":"read","members_can_create_public_repositories":false,
					"security_and_analysis":{"secret_scanning":{"status":"enabled"},
					"secret_scanning_push_protection":{"status":"enabled"}}}`))
			}
		default:
			w.WriteHeader(404)
		}
	}))
}

func TestFetchGitHubOrg_MapsConfigAndFlags(t *testing.T) {
	srv := fakeGitHub(t, true)
	defer srv.Close()

	snap, err := FetchGitHubOrg(context.Background(), srv.URL, "acme", "tok-123", srv.Client())
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if snap.Login != "acme" || snap.TwoFactorRequired || snap.DefaultRepoPermission != "write" ||
		!snap.MembersCanCreatePublicRepos || snap.SecretScanningEnabled {
		t.Fatalf("snapshot not mapped from the API: %+v", snap)
	}
	// the grounded assessor must turn that misconfig into findings
	findings := AssessGitHubOrg(snap, Options{})
	if len(findings) == 0 {
		t.Error("a misconfigured org should yield SSPM findings")
	}
}

func TestFetchGitHubOrg_HardenedYieldsZero(t *testing.T) {
	srv := fakeGitHub(t, false)
	defer srv.Close()

	snap, err := FetchGitHubOrg(context.Background(), srv.URL, "acme", "tok-123", srv.Client())
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if !snap.TwoFactorRequired || !snap.SecretScanningEnabled {
		t.Fatalf("hardened org should map secure fields: %+v", snap)
	}
	if f := AssessGitHubOrg(snap, Options{}); len(f) != 0 {
		t.Errorf("a hardened org must yield zero findings, got %d", len(f))
	}
}

func TestFetchGitHubOrg_SurfacesAPIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(`{"message":"Resource not accessible"}`))
	}))
	defer srv.Close()
	if _, err := FetchGitHubOrg(context.Background(), srv.URL, "acme", "tok-123", srv.Client()); err == nil {
		t.Error("a 403 from the org read must surface as an error, not a silent empty snapshot")
	}
}
