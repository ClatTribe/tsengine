package connector

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ClatTribe/tsengine/pkg/platform"
)

func TestGitHub_DiscoverReposToAssets(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok-123" {
			t.Errorf("missing bearer token: %q", r.Header.Get("Authorization"))
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[
			{"full_name":"acme/web","html_url":"https://github.com/acme/web","private":true,"archived":false},
			{"full_name":"acme/old","html_url":"https://github.com/acme/old","private":false,"archived":true}
		]`))
	}))
	defer srv.Close()

	g := NewGitHub("id", "secret")
	g.APIBase = srv.URL
	conn := platform.Connection{ID: "c1", TenantID: "t1", Kind: platform.ConnGitHub}

	assets, err := g.Discover(context.Background(), conn, "tok-123")
	if err != nil {
		t.Fatal(err)
	}
	// archived repo dropped; one live repo → one repository asset, tenant-scoped
	if len(assets) != 1 {
		t.Fatalf("want 1 asset (archived dropped), got %d", len(assets))
	}
	a := assets[0]
	if a.Type != "repository" || a.Target != "https://github.com/acme/web" {
		t.Errorf("asset wrong: %+v", a)
	}
	if a.TenantID != "t1" || a.ConnectionID != "c1" {
		t.Errorf("asset not scoped to tenant/connection: %+v", a)
	}
	if a.Meta["full_name"] != "acme/web" || a.Meta["private"] != "true" {
		t.Errorf("asset meta wrong: %+v", a.Meta)
	}
}

func TestGitHub_WatchPushTrigger(t *testing.T) {
	g := NewGitHub("id", "secret")
	conn := platform.Connection{ID: "c1", TenantID: "t1", Kind: platform.ConnGitHub}
	payload := []byte(`{"ref":"refs/heads/main","repository":{"full_name":"acme/web","html_url":"https://github.com/acme/web"}}`)

	trigs, err := g.Watch(context.Background(), conn, payload)
	if err != nil {
		t.Fatal(err)
	}
	if len(trigs) != 1 {
		t.Fatalf("want 1 trigger, got %d", len(trigs))
	}
	tr := trigs[0]
	if tr.Kind != platform.TriggerPush || tr.AssetTarget != "https://github.com/acme/web" || tr.TenantID != "t1" {
		t.Errorf("trigger wrong: %+v", tr)
	}

	// a non-repo payload yields no triggers, not an error
	none, err := g.Watch(context.Background(), conn, []byte(`{"zen":"ping"}`))
	if err != nil || len(none) != 0 {
		t.Errorf("non-repo event should be no-op: trigs=%v err=%v", none, err)
	}
}

func TestGitHub_OAuthURL(t *testing.T) {
	g := NewGitHub("cid", "sec")
	u := g.OAuthURL("xyz-state", "https://app/callback")
	for _, want := range []string{"client_id=cid", "state=xyz-state", "login/oauth/authorize", "scope="} {
		if !contains(u, want) {
			t.Errorf("oauth url missing %q: %s", want, u)
		}
	}
}

func TestRegistry(t *testing.T) {
	r := NewRegistry(NewGitHub("a", "b"))
	if _, err := r.Get(platform.ConnGitHub); err != nil {
		t.Errorf("github should resolve: %v", err)
	}
	if _, err := r.Get("nope"); err == nil {
		t.Error("unknown kind should error")
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
