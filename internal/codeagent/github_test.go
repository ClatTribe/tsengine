package codeagent

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestGitHubSource_ReadAndGrep: the live provider reads a file line-accurately via the Contents API (base64
// decode + slice), caches it, and greps the cached content line-accurately. Uses a fake GitHub API so no
// network/token is needed — proving the query-builder + parsing, the buildable half (the real token is the
// gated half).
func TestGitHubSource_ReadAndGrep(t *testing.T) {
	file := "package api\nfunc Search(r *http.Request){\n q := r.URL.Query().Get(\"q\")\n db.Query(\"...\"+q)\n}"
	var contentsCalls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/repos/acme/api/contents/") {
			contentsCalls++
			if r.Header.Get("Authorization") != "Bearer tok" {
				t.Errorf("missing bearer auth: %q", r.Header.Get("Authorization"))
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"content": base64.StdEncoding.EncodeToString([]byte(file)), "encoding": "base64",
			})
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	gs := NewGitHubSource("acme", "api", "main", "tok")
	gs.Base = srv.URL

	// ReadFile: line-accurate window.
	got, err := gs.ReadFile("api/handler.go", 3, 4)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, "3: ") || !strings.Contains(got, "Query().Get") || !strings.Contains(got, `db.Query`) {
		t.Errorf("read window wrong:\n%s", got)
	}

	// A second read of the same file is served from cache (no extra Contents call).
	_, _ = gs.ReadFile("api/handler.go", 1, 1)
	if contentsCalls != 1 {
		t.Errorf("second read should hit the cache, contents calls=%d", contentsCalls)
	}

	// Grep over the cached file is line-accurate.
	hits, _ := gs.Grep("Query().Get", 10)
	if len(hits) == 0 || hits[0].Path != "api/handler.go" || hits[0].Line != 3 {
		t.Errorf("grep should find the cached line 3, got %+v", hits)
	}
}

// TestGitHubSource_GroundsAgent: the live provider satisfies SourceProvider — an ungrounded record is still
// refused, a read+grounded record is accepted. (The interface contract holds regardless of the backing.)
func TestGitHubSource_GroundsAgent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/repos/o/r/contents/real.go") {
			_ = json.NewEncoder(w).Encode(map[string]any{"content": base64.StdEncoding.EncodeToString([]byte("line1\nline2")), "encoding": "base64"})
			return
		}
		http.Error(w, "not found", http.StatusNotFound)
	}))
	defer srv.Close()
	gs := NewGitHubSource("o", "r", "", "")
	gs.Base = srv.URL

	cc := &Context{Source: gs, Findings: nil}
	// citing a file the API 404s → not grounded.
	if ok, _ := cc.evidenceGrounded([]string{"ghost.go:1"}); ok {
		t.Error("a 404 path must not ground a record")
	}
	// citing a readable file → grounded.
	if ok, _ := cc.evidenceGrounded([]string{"real.go:1"}); !ok {
		t.Error("a readable path must ground a record")
	}
}
