package codelocalize

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/ClatTribe/tsengine/pkg/types"
)

func writeRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	write := func(p, c string) {
		full := filepath.Join(dir, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(c), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("store/users.go", "func Find(db *sql.DB, r *http.Request) {\n n := r.URL.Query().Get(\"n\")\n db.Query(\"SELECT * FROM u WHERE n='\"+n+\"'\")\n}")
	write("util/math.go", "package util\nfunc Add(a, b int) int { return a + b }")
	return dir
}

func TestLocalizeFinding(t *testing.T) {
	dir := writeRepo(t)
	f := types.Finding{RuleID: "semgrep::sqli", CWE: []string{"CWE-89"}, Title: "SQL injection"}
	res, err := LocalizeFinding(context.Background(), HeuristicLocalizer{}, f, dir, LoadOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Ranked) == 0 || res.Ranked[0].Path != "store/users.go" {
		t.Fatalf("expected store/users.go first, got %+v", res.TopPaths(5))
	}
}

func TestLocalizeFindings_BatchAndClean(t *testing.T) {
	dir := writeRepo(t)
	fs := []types.Finding{
		{RuleID: "sqli", CWE: []string{"CWE-89"}, Title: "SQLi"},
		{RuleID: "xxe", CWE: []string{"CWE-611"}, Title: "XXE"}, // no XXE sink in this repo → clean
	}
	locs, err := LocalizeFindings(context.Background(), HeuristicLocalizer{}, fs, dir, LoadOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(locs) != 2 {
		t.Fatalf("want 2 results in input order, got %d", len(locs))
	}
	if !locs[0].Located() || locs[0].Result.Ranked[0].Path != "store/users.go" {
		t.Fatalf("SQLi finding should locate store/users.go, got %+v", locs[0].Result.TopPaths(5))
	}
	if locs[1].Located() {
		t.Fatalf("XXE finding should localize clean in this repo, got %+v", locs[1].Result.TopPaths(5))
	}
}

func TestLocalizeFinding_BadDir(t *testing.T) {
	_, err := LocalizeFinding(context.Background(), HeuristicLocalizer{}, types.Finding{CWE: []string{"CWE-89"}}, filepath.Join(t.TempDir(), "does-not-exist"), LoadOptions{})
	// a non-existent dir walks to zero files (not an error) → clean localization, no panic.
	if err != nil {
		t.Fatalf("missing dir should degrade to empty, not error: %v", err)
	}
}
