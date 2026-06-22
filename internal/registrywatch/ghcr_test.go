package registrywatch

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// fakeGHCR serves the org packages list + per-package versions.
func fakeGHCR(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer ghp_tok" {
			t.Errorf("missing bearer: %q", r.Header.Get("Authorization"))
		}
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/orgs/acme/packages"):
			_, _ = w.Write([]byte(`[{"name":"api"},{"name":"web"}]`))
		case strings.Contains(r.URL.Path, "/packages/container/api/versions"):
			// one tagged version (two tags) + one untagged (skipped)
			_, _ = w.Write([]byte(`[
				{"name":"sha256:aaa","metadata":{"container":{"tags":["1.2.0","latest"]}}},
				{"name":"sha256:zzz","metadata":{"container":{"tags":[]}}}
			]`))
		case strings.Contains(r.URL.Path, "/packages/container/web/versions"):
			_, _ = w.Write([]byte(`[{"name":"sha256:ccc","metadata":{"container":{"tags":["prod"]}}}]`))
		default:
			http.NotFound(w, r)
		}
	}))
}

func TestGHCR_ListImages(t *testing.T) {
	srv := fakeGHCR(t)
	defer srv.Close()

	g := NewGHCR("acme", "ghp_tok")
	g.BaseURL = srv.URL
	imgs, err := g.ListImages(context.Background())
	if err != nil {
		t.Fatalf("ListImages: %v", err)
	}
	// api: 1.2.0 + latest (untagged skipped); web: prod → 3 images
	if len(imgs) != 3 {
		t.Fatalf("want 3 images, got %d: %+v", len(imgs), imgs)
	}
	byRef := map[string]string{}
	for _, i := range imgs {
		byRef[i.Ref()] = i.Digest
	}
	if byRef["ghcr.io/acme/api:1.2.0"] != "sha256:aaa" {
		t.Errorf("api:1.2.0 wrong: %+v", byRef)
	}
	if byRef["ghcr.io/acme/api:latest"] != "sha256:aaa" {
		t.Errorf("api:latest (same digest, second tag) wrong: %+v", byRef)
	}
	if byRef["ghcr.io/acme/web:prod"] != "sha256:ccc" {
		t.Errorf("web:prod wrong: %+v", byRef)
	}
}

func TestGHCR_ListThenReconcile(t *testing.T) {
	srv := fakeGHCR(t)
	defer srv.Close()
	g := NewGHCR("acme", "ghp_tok")
	g.BaseURL = srv.URL
	imgs, err := g.ListImages(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	r1 := Reconcile(imgs, nil)
	if r1.New != 3 {
		t.Fatalf("first reconcile: want 3 new, got %d", r1.New)
	}
	r2 := Reconcile(imgs, r1.NextSeen)
	if len(r2.ToScan) != 0 {
		t.Errorf("second reconcile should be a no-op, got %+v", r2.ToScan)
	}
}

func TestGHCR_UserScopeAndOwnerRequired(t *testing.T) {
	var hitUserPath bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/users/me/packages") {
			hitUserPath = true
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[]`))
	}))
	defer srv.Close()
	g := NewGHCR("me", "ghp_tok")
	g.IsUser = true
	g.BaseURL = srv.URL
	if _, err := g.ListImages(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !hitUserPath {
		t.Error("IsUser must hit the /users/{owner}/packages path")
	}
	if _, err := NewGHCR("", "t").ListImages(context.Background()); err == nil {
		t.Error("empty owner must error")
	}
}
