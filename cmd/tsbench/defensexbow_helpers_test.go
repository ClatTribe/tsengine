package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/internal/bench"
	"github.com/ClatTribe/tsengine/internal/codeagent"
)

// TestFilterXBOWDefense: selection by id and by vuln-class category (first tag).
func TestFilterXBOWDefense(t *testing.T) {
	in := []bench.XBOWBenchmark{
		{ID: "XBEN-001-24", Config: bench.XBOWConfig{Tags: []string{"idor"}}},
		{ID: "XBEN-002-24", Config: bench.XBOWConfig{Tags: []string{"sqli"}}},
		{ID: "XBEN-003-24", Config: bench.XBOWConfig{Tags: []string{"sqli"}}},
	}
	if got := filterXBOWDefense(in, "xben-002-24", ""); len(got) != 1 || got[0].ID != "XBEN-002-24" {
		t.Errorf("--only should select one by id (case-insensitive), got %+v", got)
	}
	if got := filterXBOWDefense(in, "", "sqli"); len(got) != 2 {
		t.Errorf("--category sqli should select 2, got %d", len(got))
	}
	if got := filterXBOWDefense(in, "", ""); len(got) != 3 {
		t.Errorf("no filter → all, got %d", len(got))
	}
}

// TestGatherSource: collects app source, skips binaries/oversize/vendored trees, respects the total cap.
func TestGatherSource(t *testing.T) {
	dir := t.TempDir()
	write := func(rel, content string) {
		p := filepath.Join(dir, rel)
		_ = os.MkdirAll(filepath.Dir(p), 0o755)
		_ = os.WriteFile(p, []byte(content), 0o644)
	}
	write("app/login.php", "<?php // vulnerable")
	write("Dockerfile", "FROM php:7.4-apache")
	write("static/logo.png", "\x89PNG binarydata")       // binary ext → skipped
	write("node_modules/dep/index.js", "module.exports") // vendored → skipped
	write("big.php", strings.Repeat("x", 60<<10))        // > 48KB per-file cap → skipped

	files := gatherSource(dir)
	got := map[string]bool{}
	for _, f := range files {
		got[f.Path] = true
	}
	if !got["app/login.php"] || !got["Dockerfile"] {
		t.Errorf("should collect app source + Dockerfile, got %v", got)
	}
	if got["static/logo.png"] || got["node_modules/dep/index.js"] || got["big.php"] {
		t.Errorf("should skip binary/vendored/oversize, got %v", got)
	}
}

// TestApplyPatch: writes replacements into the work dir and refuses an escape.
func TestApplyPatch(t *testing.T) {
	work := t.TempDir()
	_ = os.WriteFile(filepath.Join(work, "login.php"), []byte("old"), 0o644)
	err := applyPatch(work, []codeagent.PatchedFile{
		{Path: "login.php", Content: "<?php // fixed"},
		{Path: "sub/new.php", Content: "<?php echo 1;"},
	})
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if b, _ := os.ReadFile(filepath.Join(work, "login.php")); string(b) != "<?php // fixed" {
		t.Errorf("login.php not patched: %q", b)
	}
	if b, _ := os.ReadFile(filepath.Join(work, "sub/new.php")); !strings.Contains(string(b), "echo 1") {
		t.Errorf("nested file not written: %q", b)
	}
	// An escaping path is silently refused (never writes outside work).
	_ = applyPatch(work, []codeagent.PatchedFile{{Path: "../escape.php", Content: "x"}})
	if _, err := os.Stat(filepath.Join(filepath.Dir(work), "escape.php")); err == nil {
		t.Error("applyPatch must never write outside the work dir")
	}
}

// TestCopyBenchmarkDir: copies the tree, skips .git, returns a working cleanup.
func TestCopyBenchmarkDir(t *testing.T) {
	src := t.TempDir()
	_ = os.WriteFile(filepath.Join(src, "docker-compose.yml"), []byte("services: {}"), 0o644)
	_ = os.MkdirAll(filepath.Join(src, ".git"), 0o755)
	_ = os.WriteFile(filepath.Join(src, ".git", "HEAD"), []byte("ref"), 0o644)
	_ = os.MkdirAll(filepath.Join(src, "app"), 0o755)
	_ = os.WriteFile(filepath.Join(src, "app", "index.php"), []byte("<?php"), 0o644)

	work, cleanup, err := copyBenchmarkDir(src)
	if err != nil {
		t.Fatalf("copy: %v", err)
	}
	defer cleanup()
	if composeIn(work) == "" {
		t.Error("copied dir should have the compose file")
	}
	if _, err := os.Stat(filepath.Join(work, "app", "index.php")); err != nil {
		t.Error("app source should be copied")
	}
	if _, err := os.Stat(filepath.Join(work, ".git", "HEAD")); err == nil {
		t.Error(".git must be skipped in the copy")
	}
	cleanup()
	if _, err := os.Stat(work); err == nil {
		t.Error("cleanup should remove the work dir")
	}
}
