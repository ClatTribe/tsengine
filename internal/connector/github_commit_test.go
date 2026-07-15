package connector

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/pkg/platform"
)

// fakeGitHub records the Git Data API calls a fix-PR must make.
type fakeGitHub struct {
	calls    []string
	blobs    []string // blob contents in creation order
	treeEnts []map[string]any
	commit   map[string]any
	ref      map[string]any
	pr       map[string]any
}

func (f *fakeGitHub) server(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	rec := func(name string, w http.ResponseWriter, r *http.Request, resp any, capture func(map[string]any)) {
		f.calls = append(f.calls, name)
		if r.Body != nil && capture != nil {
			raw, _ := io.ReadAll(r.Body)
			var body map[string]any
			_ = json.Unmarshal(raw, &body)
			capture(body)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}
	mux.HandleFunc("/repos/acme/app/git/ref/heads/main", func(w http.ResponseWriter, r *http.Request) {
		rec("get-ref", w, r, map[string]any{"object": map[string]any{"sha": "basecommit1"}}, nil)
	})
	mux.HandleFunc("/repos/acme/app/git/commits/basecommit1", func(w http.ResponseWriter, r *http.Request) {
		rec("get-commit", w, r, map[string]any{"tree": map[string]any{"sha": "basetree1"}}, nil)
	})
	mux.HandleFunc("/repos/acme/app/git/blobs", func(w http.ResponseWriter, r *http.Request) {
		rec("create-blob", w, r, map[string]any{"sha": "blob" + itoa(len(f.blobs)+1)}, func(b map[string]any) {
			f.blobs = append(f.blobs, b["content"].(string))
		})
	})
	mux.HandleFunc("/repos/acme/app/git/trees", func(w http.ResponseWriter, r *http.Request) {
		rec("create-tree", w, r, map[string]any{"sha": "newtree1"}, func(b map[string]any) {
			for _, e := range b["tree"].([]any) {
				f.treeEnts = append(f.treeEnts, e.(map[string]any))
			}
			if b["base_tree"] != "basetree1" {
				t.Errorf("tree must build on the base tree, got %v", b["base_tree"])
			}
		})
	})
	mux.HandleFunc("/repos/acme/app/git/commits", func(w http.ResponseWriter, r *http.Request) {
		rec("create-commit", w, r, map[string]any{"sha": "newcommit1"}, func(b map[string]any) { f.commit = b })
	})
	mux.HandleFunc("/repos/acme/app/git/refs", func(w http.ResponseWriter, r *http.Request) {
		rec("create-ref", w, r, map[string]any{"ref": "ok"}, func(b map[string]any) { f.ref = b })
	})
	mux.HandleFunc("/repos/acme/app/pulls", func(w http.ResponseWriter, r *http.Request) {
		rec("open-pr", w, r, map[string]any{"number": 7}, func(b map[string]any) { f.pr = b })
	})
	return httptest.NewServer(mux)
}

func itoa(i int) string { return string(rune('0' + i)) }

// TestApply_CommitsFixThenOpensPR is the production gap this closes: an action carrying the actual fix
// must land as a real commit on a new branch, and the PR must point at it — not an empty PR.
func TestApply_CommitsFixThenOpensPR(t *testing.T) {
	f := &fakeGitHub{}
	srv := f.server(t)
	defer srv.Close()
	g := &GitHub{APIBase: srv.URL, HTTP: srv.Client()}

	act := platform.Action{
		ID: "act-Abc123", Kind: platform.ActOpenPR, Title: "Fix SQL injection in login",
		Payload: map[string]any{
			"full_name": "acme/app",
			"body":      "closes finding f-1",
			"files":     map[string]any{"app/login.php": "<?php // fixed", "app/db.php": "<?php // helper"},
		},
	}
	if err := g.Apply(context.Background(), platform.Connection{}, "tok", act); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	want := []string{"get-ref", "get-commit", "create-blob", "create-blob", "create-tree", "create-commit", "create-ref", "open-pr"}
	if strings.Join(f.calls, ",") != strings.Join(want, ",") {
		t.Errorf("call sequence:\n got %v\nwant %v", f.calls, want)
	}
	if len(f.blobs) != 2 {
		t.Fatalf("want 2 blobs (one per changed file), got %d", len(f.blobs))
	}
	// deterministic order → app/db.php sorts before app/login.php
	if f.blobs[0] != "<?php // helper" || f.blobs[1] != "<?php // fixed" {
		t.Errorf("blob contents/order wrong: %q", f.blobs)
	}
	if f.commit["tree"] != "newtree1" {
		t.Errorf("commit must use the new tree, got %v", f.commit["tree"])
	}
	if ps, ok := f.commit["parents"].([]any); !ok || len(ps) != 1 || ps[0] != "basecommit1" {
		t.Errorf("commit must parent the base commit, got %v", f.commit["parents"])
	}
	branch := "tsengine/fix-act-abc123"
	if f.ref["ref"] != "refs/heads/"+branch {
		t.Errorf("ref: got %v want refs/heads/%s", f.ref["ref"], branch)
	}
	if f.ref["sha"] != "newcommit1" {
		t.Errorf("ref must point at the new commit, got %v", f.ref["sha"])
	}
	if f.pr["head"] != branch || f.pr["base"] != "main" {
		t.Errorf("PR must open from the fix branch: head=%v base=%v", f.pr["head"], f.pr["base"])
	}
}

// TestApply_NoFilesKeepsLegacyBehaviour: an action with no fix files must NOT touch the Git Data API
// (back-compat with the existing prose-PR path).
func TestApply_NoFilesKeepsLegacyBehaviour(t *testing.T) {
	f := &fakeGitHub{}
	srv := f.server(t)
	defer srv.Close()
	g := &GitHub{APIBase: srv.URL, HTTP: srv.Client()}
	act := platform.Action{
		ID: "a1", Kind: platform.ActOpenPR,
		Payload: map[string]any{"full_name": "acme/app", "head": "existing-branch", "body": "advice"},
	}
	if err := g.Apply(context.Background(), platform.Connection{}, "tok", act); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if strings.Join(f.calls, ",") != "open-pr" {
		t.Errorf("no files → PR only, got %v", f.calls)
	}
}

// TestFetchFile reads real source (the input an honest fix needs) and refuses anything it can't
// actually read — never a silently-empty "source" the model would hallucinate against.
func TestFetchFile(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/acme/app/contents/app/login.php", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("ref") != "main" {
			t.Errorf("ref not threaded: %q", r.URL.Query().Get("ref"))
		}
		// GitHub wraps base64 at 60 cols
		enc := base64.StdEncoding.EncodeToString([]byte("<?php $q=\"SELECT $u\";"))
		_ = json.NewEncoder(w).Encode(map[string]any{"type": "file", "encoding": "base64", "content": enc[:4] + "\n" + enc[4:]})
	})
	mux.HandleFunc("/repos/acme/app/contents/app", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"type": "dir"})
	})
	mux.HandleFunc("/repos/acme/app/contents/huge.bin", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"type": "file", "encoding": "none", "size": 9000000})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	g := &GitHub{APIBase: srv.URL, HTTP: srv.Client()}

	got, err := g.FetchFile(context.Background(), "tok", "acme/app", "main", "app/login.php")
	if err != nil {
		t.Fatalf("FetchFile: %v", err)
	}
	if got != "<?php $q=\"SELECT $u\";" {
		t.Errorf("decoded content wrong: %q", got)
	}
	if _, err := g.FetchFile(context.Background(), "tok", "acme/app", "", "app"); err == nil {
		t.Error("a directory must be an error, not empty source")
	}
	if _, err := g.FetchFile(context.Background(), "tok", "acme/app", "", "huge.bin"); err == nil {
		t.Error("a too-large/no-inline-content file must be an error, not empty source")
	}
}

// TestCommitFiles_RefusesEmptyPatch: never commit nothing (no fabricated "fix").
func TestCommitFiles_RefusesEmptyPatch(t *testing.T) {
	g := &GitHub{APIBase: "http://unused"}
	if err := g.CommitFiles(context.Background(), "t", "acme/app", "main", "b", "m", nil); err == nil {
		t.Error("want an error for an empty patch")
	}
}
