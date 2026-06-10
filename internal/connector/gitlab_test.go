package connector

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ClatTribe/tsengine/pkg/platform"
)

func TestGitLab_DiscoverProjectsToAssets(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok" {
			t.Errorf("missing bearer: %q", r.Header.Get("Authorization"))
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[
			{"path_with_namespace":"acme/web","web_url":"https://gitlab.com/acme/web","visibility":"private","archived":false},
			{"path_with_namespace":"acme/old","web_url":"https://gitlab.com/acme/old","visibility":"public","archived":true}
		]`))
	}))
	defer srv.Close()

	g := NewGitLab("id", "sec")
	g.BaseURL = srv.URL
	assets, err := g.Discover(context.Background(), platform.Connection{ID: "c1", TenantID: "t1"}, "tok")
	if err != nil {
		t.Fatal(err)
	}
	if len(assets) != 1 { // archived dropped
		t.Fatalf("want 1 asset, got %d", len(assets))
	}
	a := assets[0]
	if a.Type != "repository" || a.Target != "https://gitlab.com/acme/web" || a.ConnectionID != "c1" {
		t.Errorf("asset wrong: %+v", a)
	}
	if a.Meta["path"] != "acme/web" {
		t.Errorf("asset meta wrong: %+v", a.Meta)
	}
}

func TestGitLab_WatchPushHook(t *testing.T) {
	g := NewGitLab("a", "b")
	trigs, err := g.Watch(context.Background(), platform.Connection{ID: "c1", TenantID: "t1"},
		[]byte(`{"object_kind":"push","project":{"web_url":"https://gitlab.com/acme/web"}}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(trigs) != 1 || trigs[0].Kind != platform.TriggerPush || trigs[0].AssetTarget != "https://gitlab.com/acme/web" {
		t.Errorf("trigger wrong: %+v", trigs)
	}
	// a non-push hook is a no-op
	if n, _ := g.Watch(context.Background(), platform.Connection{}, []byte(`{"object_kind":"tag_push"}`)); len(n) != 0 {
		t.Errorf("non-push hook should be no-op, got %+v", n)
	}
}

func TestGitLab_OAuthURLAndKind(t *testing.T) {
	g := NewGitLab("cid", "sec")
	if g.Kind() != platform.ConnGitLab {
		t.Errorf("kind = %q", g.Kind())
	}
	u := g.OAuthURL("st", "https://app/cb")
	for _, want := range []string{"client_id=cid", "state=st", "oauth/authorize", "response_type=code"} {
		if !contains(u, want) {
			t.Errorf("oauth url missing %q: %s", want, u)
		}
	}
}

func TestGitLab_ApplyOpensMR(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()
	g := NewGitLab("a", "b")
	g.BaseURL = srv.URL
	act := platform.Action{Kind: platform.ActOpenPR, Title: "fix", Payload: map[string]any{"path": "acme/web", "head": "tsengine/fix", "base": "main"}}
	if err := g.Apply(context.Background(), platform.Connection{}, "tok", act); err != nil {
		t.Fatal(err)
	}
	if gotPath == "" || !contains(gotPath, "merge_requests") {
		t.Errorf("apply should POST a merge request, hit %q", gotPath)
	}
}
