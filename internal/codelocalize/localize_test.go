package codelocalize

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/ClatTribe/tsengine/pkg/types"
)

func sqliSink() File {
	return File{Path: "app/users.go", Content: `package app
import "database/sql"
func getUser(db *sql.DB, r *http.Request) {
	name := r.URL.Query().Get("name")
	rows, _ := db.Query("SELECT * FROM users WHERE name = '" + name + "'")
	_ = rows
}`}
}

func xssSink() File {
	return File{Path: "web/render.js", Content: `function show(req, res) {
	const q = req.query.q;
	res.send("<div>" + q + "</div>");
	document.getElementById("out").innerHTML = q;
}`}
}

func cleanFile() File {
	return File{Path: "util/math.go", Content: `package util
func Add(a, b int) int { return a + b }
func Mul(a, b int) int { return a * b }`}
}

func TestHeuristicLocalize_RanksSinkAboveClean(t *testing.T) {
	repo := Repo{cleanFile(), sqliSink(), xssSink()}
	res, err := HeuristicLocalizer{}.Localize(context.Background(), Query{CWE: []string{"CWE-89"}}, repo)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Ranked) == 0 {
		t.Fatal("expected at least one candidate")
	}
	if res.Ranked[0].Path != "app/users.go" {
		t.Fatalf("SQLi sink should rank first, got %q (ranked=%+v)", res.Ranked[0].Path, res.Ranked)
	}
	// the clean file must never appear (FP-control).
	for _, c := range res.Ranked {
		if c.Path == "util/math.go" {
			t.Fatalf("clean file leaked into ranking: %+v", res.Ranked)
		}
	}
	// evidence must cite a real line.
	if len(res.Ranked[0].Reasons) == 0 {
		t.Fatal("top candidate carries no evidence reasons")
	}
}

func TestHeuristicLocalize_CleanRepoIsEmpty(t *testing.T) {
	repo := Repo{cleanFile(), {Path: "util/str.go", Content: "package util\nfunc Rev(s string) string { return s }"}}
	res, err := HeuristicLocalizer{}.Localize(context.Background(), Query{CWE: []string{"CWE-89"}}, repo)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Ranked) != 0 {
		t.Fatalf("clean repo must localize empty, got %+v", res.Ranked)
	}
}

func TestHeuristicLocalize_SourceSinkCooccurrenceRanksHigher(t *testing.T) {
	// both files carry a SQL sink token; only the first also has a taint source → it should outrank.
	tainted := File{Path: "a/taint.go", Content: `name := r.URL.Query().Get("n")
db.Query("SELECT x FROM t WHERE n='" + name + "'")`}
	incidental := File{Path: "b/incidental.go", Content: `// admin bootstrap
db.Query("SELECT count(*) FROM t")`}
	repo := Repo{incidental, tainted}
	res, _ := HeuristicLocalizer{}.Localize(context.Background(), Query{CWE: []string{"CWE-89"}}, repo)
	if res.Ranked[0].Path != "a/taint.go" {
		t.Fatalf("source→sink co-occurrence should rank first, got %q", res.Ranked[0].Path)
	}
}

func TestHeuristicLocalize_UnknownCWEFallsBackToKeywords(t *testing.T) {
	repo := Repo{
		cleanFile(),
		{Path: "auth/session.go", Content: "// handles the session fixation edge case\nfunc rotate() {}"},
	}
	// CWE-384 (session fixation) isn't in the sink table → keyword-only from the description.
	res, _ := HeuristicLocalizer{}.Localize(context.Background(), Query{
		CWE:         []string{"CWE-384"},
		Description: "session fixation lets an attacker reuse a session",
	}, repo)
	if len(res.Ranked) == 0 || res.Ranked[0].Path != "auth/session.go" {
		t.Fatalf("keyword fallback should surface the session file, got %+v", res.Ranked)
	}
	if res.Trace[0] == "" {
		t.Fatal("expected a trace explaining the keyword fallback")
	}
}

func TestNormalizeCWE(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"CWE-89", "CWE-89"}, {"cwe-89", "CWE-89"}, {"89", "CWE-89"}, {" CWE-79 ", "CWE-79"}, {"", ""},
	} {
		if got := normalizeCWE(tc.in); got != tc.want {
			t.Errorf("normalizeCWE(%q)=%q want %q", tc.in, got, tc.want)
		}
	}
}

func TestQueryFromFindingAndKeywords(t *testing.T) {
	q := QueryFromFinding(types.Finding{
		CWE:         []string{"CWE-89"},
		Title:       "SQL Injection in search",
		Description: "The attacker could inject via the query parameter",
	})
	if len(q.CWE) != 1 || q.CWE[0] != "CWE-89" {
		t.Fatalf("CWE not carried: %+v", q.CWE)
	}
	kw := q.keywords()
	// stopwords ("attacker","could","query","the") and short tokens must be dropped.
	for _, bad := range []string{"the", "could", "attacker"} {
		for _, k := range kw {
			if k == bad {
				t.Errorf("stopword %q leaked into keywords %v", bad, kw)
			}
		}
	}
	// a real content word survives.
	found := false
	for _, k := range kw {
		if k == "search" || k == "inject" || k == "parameter" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected a content keyword in %v", kw)
	}
}

func TestResultTopPaths(t *testing.T) {
	r := Result{Ranked: []Candidate{{Path: "a"}, {Path: "b"}, {Path: "c"}}}
	got := r.TopPaths(2)
	if len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Fatalf("TopPaths(2)=%v", got)
	}
	if len(r.TopPaths(10)) != 3 {
		t.Fatal("TopPaths beyond len should clamp")
	}
}

func TestLoadRepo(t *testing.T) {
	dir := t.TempDir()
	must := func(p, c string) {
		full := filepath.Join(dir, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(c), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	must("app/main.go", "package main")
	must("web/app.ts", "const x = 1")
	must("assets/logo.png", "\x89PNG binary")
	must("node_modules/dep/index.js", "module.exports = {}")

	repo, err := LoadRepo(dir, LoadOptions{})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, f := range repo {
		got[f.Path] = true
	}
	if !got["app/main.go"] || !got["web/app.ts"] {
		t.Fatalf("source files missing: %v", got)
	}
	if got["assets/logo.png"] {
		t.Error("non-source .png should be skipped")
	}
	if got["node_modules/dep/index.js"] {
		t.Error("node_modules should be skipped")
	}
}

func TestLoadRepo_RespectsFileCap(t *testing.T) {
	dir := t.TempDir()
	big := make([]byte, 2048)
	os.WriteFile(filepath.Join(dir, "big.go"), big, 0o644)
	repo, err := LoadRepo(dir, LoadOptions{MaxFileBytes: 1024})
	if err != nil {
		t.Fatal(err)
	}
	if len(repo) != 0 {
		t.Fatalf("oversized file should be skipped, got %d files", len(repo))
	}
}
