package registrywatch

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// fakeHub serves the two Docker Hub endpoints we use: repo list + per-repo tag list.
func fakeHub(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/repositories/acme/"):
			_, _ = w.Write([]byte(`{"next":"","results":[{"name":"api"},{"name":"web"}]}`))
		case strings.Contains(r.URL.Path, "/repositories/acme/api/tags"):
			// one tag with a top-level digest, one relying on images[0].digest, one undigested (skipped)
			_, _ = w.Write([]byte(`{"next":"","results":[
				{"name":"1.2.0","digest":"sha256:aaa"},
				{"name":"latest","images":[{"digest":"sha256:bbb"}]},
				{"name":"broken"}
			]}`))
		case strings.Contains(r.URL.Path, "/repositories/acme/web/tags"):
			_, _ = w.Write([]byte(`{"next":"","results":[{"name":"prod","digest":"sha256:ccc"}]}`))
		default:
			http.NotFound(w, r)
		}
	}))
}

func TestDockerHub_ListImages(t *testing.T) {
	srv := fakeHub(t)
	defer srv.Close()

	dh := NewDockerHub("acme", "")
	dh.BaseURL = srv.URL
	imgs, err := dh.ListImages(context.Background())
	if err != nil {
		t.Fatalf("ListImages: %v", err)
	}
	// api: 1.2.0 + latest (broken skipped); web: prod → 3 images total
	if len(imgs) != 3 {
		t.Fatalf("want 3 images, got %d: %+v", len(imgs), imgs)
	}
	byRef := map[string]string{}
	for _, i := range imgs {
		byRef[i.Ref()] = i.Digest
	}
	if byRef["acme/api:1.2.0"] != "sha256:aaa" {
		t.Errorf("api:1.2.0 digest wrong: %q", byRef["acme/api:1.2.0"])
	}
	if byRef["acme/api:latest"] != "sha256:bbb" { // fell back to images[0].digest
		t.Errorf("api:latest should use images[0].digest, got %q", byRef["acme/api:latest"])
	}
	if byRef["acme/web:prod"] != "sha256:ccc" {
		t.Errorf("web:prod digest wrong: %q", byRef["acme/web:prod"])
	}
}

func TestDockerHub_ListThenReconcile(t *testing.T) {
	srv := fakeHub(t)
	defer srv.Close()
	dh := NewDockerHub("acme", "")
	dh.BaseURL = srv.URL
	imgs, err := dh.ListImages(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	// First reconcile (nothing seen) → all 3 are new.
	r1 := Reconcile(imgs, nil)
	if r1.New != 3 || len(r1.ToScan) != 3 {
		t.Fatalf("first reconcile: want 3 new, got new=%d scan=%d", r1.New, len(r1.ToScan))
	}
	// Second reconcile against the persisted state → nothing to scan.
	r2 := Reconcile(imgs, r1.NextSeen)
	if r2.New != 0 || r2.Updated != 0 || len(r2.ToScan) != 0 {
		t.Errorf("second reconcile should be a no-op, got %+v", r2)
	}
}

func TestDockerHub_RequiresNamespace(t *testing.T) {
	if _, err := NewDockerHub("", "").ListImages(context.Background()); err == nil {
		t.Error("empty namespace must error")
	}
}

func TestDockerHub_MaxImagesCaps(t *testing.T) {
	srv := fakeHub(t)
	defer srv.Close()
	dh := NewDockerHub("acme", "")
	dh.BaseURL = srv.URL
	dh.MaxImages = 1
	imgs, err := dh.ListImages(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(imgs) != 1 {
		t.Errorf("MaxImages=1 must cap to 1, got %d", len(imgs))
	}
}
