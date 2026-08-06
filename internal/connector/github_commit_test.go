package connector

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/pkg/platform"
)

// fakeGitHub emulates the Git Data API well enough to assert the whole commit sequence.
type fakeGitHub struct {
	calls   []string          // method+path, in order
	blobs   []string          // decoded blob contents, in creation order
	treeReq map[string]any    // the create-tree body
	ref     map[string]any    // the create-ref body
	commit  map[string]any    // the create-commit body
	status  map[string]int    // path substring → forced status
	files   map[string]string // path → content for the contents API
}

func (f *fakeGitHub) server(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.calls = append(f.calls, r.Method+" "+r.URL.Path)
		for frag, code := range f.status {
			if strings.Contains(r.URL.Path, frag) {
				w.WriteHeader(code)
				_, _ = w.Write([]byte(`{"message":"forced"}`))
				return
			}
		}
		var body map[string]any
		if r.Body != nil {
			_ = json.NewDecoder(r.Body).Decode(&body)
		}
		switch {
		case strings.Contains(r.URL.Path, "/git/ref/heads/"):
			_, _ = w.Write([]byte(`{"object":{"sha":"basesha"}}`))
		case strings.Contains(r.URL.Path, "/git/commits/"): // GET base commit
			_, _ = w.Write([]byte(`{"tree":{"sha":"basetree"}}`))
		case strings.Contains(r.URL.Path, "/git/blobs"):
			raw, _ := base64.StdEncoding.DecodeString(body["content"].(string))
			f.blobs = append(f.blobs, string(raw))
			_, _ = w.Write([]byte(`{"sha":"blob` + string(rune('0'+len(f.blobs))) + `"}`))
		case strings.Contains(r.URL.Path, "/git/trees"):
			f.treeReq = body
			_, _ = w.Write([]byte(`{"sha":"newtree"}`))
		case strings.Contains(r.URL.Path, "/git/commits"): // POST new commit
			f.commit = body
			_, _ = w.Write([]byte(`{"sha":"newcommit"}`))
		case strings.Contains(r.URL.Path, "/git/refs"):
			f.ref = body
			_, _ = w.Write([]byte(`{"ref":"ok"}`))
		case strings.Contains(r.URL.Path, "/contents/"):
			p := strings.SplitN(r.URL.Path, "/contents/", 2)[1]
			c, ok := f.files[p]
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			_, _ = w.Write([]byte(`{"encoding":"base64","content":"` + base64.StdEncoding.EncodeToString([]byte(c)) + `"}`))
		case strings.Contains(r.URL.Path, "/pulls"):
			_, _ = w.Write([]byte(`{"number":1}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

func ghWith(t *testing.T, f *fakeGitHub) (*GitHub, func()) {
	t.Helper()
	srv := f.server(t)
	g := NewGitHub("id", "secret")
	g.APIBase = srv.URL
	return g, srv.Close
}

// The whole point: a multi-file patch becomes ONE atomic commit on a NEW branch, so the PR carries a
// real diff. Before this the PR pointed at a branch nothing had created.
func TestCommitFiles_CreatesOneAtomicCommitOnANewBranch(t *testing.T) {
	f := &fakeGitHub{}
	g, done := ghWith(t, f)
	defer done()

	err := g.CommitFiles(context.Background(), "tok", "acme/web", "main", "tsengine/fix-sqli", "fix: parameterize query",
		map[string]string{"db.py": "cur.execute(q, (name,))", "api.py": "sanitize(x)"})
	if err != nil {
		t.Fatal(err)
	}

	// Both files uploaded, in DETERMINISTIC path order (api.py before db.py) so the same patch
	// reproduces the same tree.
	if len(f.blobs) != 2 || f.blobs[0] != "sanitize(x)" {
		t.Fatalf("blobs wrong (want api.py first): %q", f.blobs)
	}
	// ONE tree extending the base, ONE commit with the base as parent, ONE new ref.
	if f.treeReq["base_tree"] != "basetree" {
		t.Errorf("tree must extend the base tree: %v", f.treeReq)
	}
	if got := f.treeReq["tree"].([]any); len(got) != 2 {
		t.Errorf("both files must be in a single tree, got %d entries", len(got))
	}
	if f.commit["tree"] != "newtree" || f.commit["message"] != "fix: parameterize query" {
		t.Errorf("commit wrong: %v", f.commit)
	}
	if parents, _ := f.commit["parents"].([]any); len(parents) != 1 || parents[0] != "basesha" {
		t.Errorf("commit must parent the base sha: %v", f.commit["parents"])
	}
	if f.ref["ref"] != "refs/heads/tsengine/fix-sqli" || f.ref["sha"] != "newcommit" {
		t.Errorf("branch ref wrong: %v", f.ref)
	}
}

// An empty patch must be refused: an empty branch produces a PR with no diff, which is a misleading
// artifact — it looks like a fix shipped when nothing changed.
func TestCommitFiles_RefusesEmptyPatch(t *testing.T) {
	f := &fakeGitHub{}
	g, done := ghWith(t, f)
	defer done()

	err := g.CommitFiles(context.Background(), "tok", "acme/web", "main", "b", "m", nil)
	if err == nil || !strings.Contains(err.Error(), "empty patch") {
		t.Fatalf("want an empty-patch refusal, got %v", err)
	}
	if len(f.calls) != 0 {
		t.Errorf("must not call GitHub at all for an empty patch, got %v", f.calls)
	}
}

// A 403 is almost always "the App lacks contents: write". It must be surfaced with that hint, never
// swallowed into a silent "fixed".
func TestCommitFiles_SurfacesMissingWriteScope(t *testing.T) {
	f := &fakeGitHub{status: map[string]int{"/git/blobs": http.StatusForbidden}}
	g, done := ghWith(t, f)
	defer done()

	err := g.CommitFiles(context.Background(), "tok", "acme/web", "main", "b", "m", map[string]string{"a.py": "x"})
	if err == nil {
		t.Fatal("a 403 must surface as an error")
	}
	if !strings.Contains(err.Error(), "contents: write") {
		t.Errorf("the error should name the likely missing scope: %v", err)
	}
}

func TestFetchFile_ReadsAndDecodes(t *testing.T) {
	f := &fakeGitHub{files: map[string]string{"app/db.py": "cur.execute(f\"...{name}\")"}}
	g, done := ghWith(t, f)
	defer done()

	got, err := g.FetchFile(context.Background(), "tok", "acme/web", "app/db.py", "main")
	if err != nil {
		t.Fatal(err)
	}
	if got != "cur.execute(f\"...{name}\")" {
		t.Fatalf("content wrong: %q", got)
	}
	if _, err := g.FetchFile(context.Background(), "tok", "acme/web", "missing.py", ""); err == nil {
		t.Error("a missing file must error, not return empty content")
	}
}

// Apply must now commit the patch BEFORE opening the PR — otherwise the PR references a branch that
// does not exist and the fix never reaches the customer.
func TestApply_CommitsPatchThenOpensPR(t *testing.T) {
	f := &fakeGitHub{}
	g, done := ghWith(t, f)
	defer done()

	err := g.Apply(context.Background(), platform.Connection{}, "tok", platform.Action{
		Kind:  platform.ActOpenPR,
		Title: "fix: SQL injection",
		Payload: map[string]any{
			"full_name": "acme/web", "head": "tsengine/fix-1", "base": "main",
			"files": map[string]any{"db.py": "cur.execute(q, (name,))"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(f.calls, " | ")
	if !strings.Contains(joined, "/git/refs") || !strings.Contains(joined, "/pulls") {
		t.Fatalf("expected a commit then a PR, got: %s", joined)
	}
	// Ordering matters: the branch must exist before the PR references it.
	if strings.Index(joined, "/git/refs") > strings.Index(joined, "/pulls") {
		t.Errorf("the branch must be created BEFORE the PR: %s", joined)
	}
}

// Back-compat: an action with no files behaves exactly as before (PR only, no commit calls).
func TestApply_WithoutFilesIsUnchanged(t *testing.T) {
	f := &fakeGitHub{}
	g, done := ghWith(t, f)
	defer done()

	err := g.Apply(context.Background(), platform.Connection{}, "tok", platform.Action{
		Kind:    platform.ActOpenPR,
		Payload: map[string]any{"full_name": "acme/web", "head": "existing-branch"},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range f.calls {
		if strings.Contains(c, "/git/") {
			t.Errorf("no patch supplied → no git-data calls, got %v", f.calls)
		}
	}
}

// A patch with no head branch is a configuration error, not something to guess at.
func TestApply_PatchWithoutHeadBranchErrors(t *testing.T) {
	f := &fakeGitHub{}
	g, done := ghWith(t, f)
	defer done()

	err := g.Apply(context.Background(), platform.Connection{}, "tok", platform.Action{
		Kind:    platform.ActOpenPR,
		Payload: map[string]any{"full_name": "acme/web", "files": map[string]any{"a.py": "x"}},
	})
	if err == nil || !strings.Contains(err.Error(), "head branch") {
		t.Fatalf("want a clear head-branch error, got %v", err)
	}
}

// A non-string value must be SKIPPED, never coerced — committing a stringified number as file
// content would corrupt the file, and a corrupted fix is worse than no fix.
func TestFilesFrom_SkipsNonStringValues(t *testing.T) {
	got := filesFrom(map[string]any{"files": map[string]any{"a.py": "ok", "b.py": 42}})
	if len(got) != 1 || got["a.py"] != "ok" {
		t.Fatalf("non-string content must be skipped, got %v", got)
	}
	if filesFrom(nil) != nil || filesFrom(map[string]any{}) != nil {
		t.Error("absent files must yield nil")
	}
	typed := filesFrom(map[string]any{"files": map[string]string{"a.py": "ok"}})
	if len(typed) != 1 {
		t.Error("a typed map[string]string must also be accepted")
	}
}
