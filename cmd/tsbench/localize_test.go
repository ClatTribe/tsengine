package main

import (
	"io"
	"os"
	"strings"
	"testing"
)

// captureStdout runs fn with os.Stdout redirected and returns what it printed.
func captureStdout(t *testing.T, fn func() error) (string, error) {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	runErr := fn()
	w.Close()
	os.Stdout = old
	out, _ := io.ReadAll(r)
	return string(out), runErr
}

// End-to-end guard on the `tsbench localize` benchmark path: the deterministic (no-key) run must produce
// the Antares-cited scorecard with a perfect aggregate over the built-in corpus. Locks the whole CLI →
// bench → localizer wiring against regression.
func TestLocalizeCmd_BenchmarkGolden(t *testing.T) {
	out, err := captureStdout(t, func() error { return localizeCmd(nil) })
	if err != nil {
		t.Fatalf("localizeCmd: %v", err)
	}
	for _, want := range []string{"Vulnerability-Localization Benchmark", "Antares", "AGGREGATE"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
	// the substrate must localize the whole corpus perfectly — a regression would drop this below 1.00.
	if !strings.Contains(out, "**AGGREGATE** | heuristic | **1.00** | **1.00** | **1.00**") {
		t.Fatalf("aggregate not perfect — a localizer regression:\n%s", out)
	}
}

func TestLocalizeCmd_RepoModeRequiresCWE(t *testing.T) {
	err := localizeCmd([]string{"--repo", t.TempDir()})
	if err == nil || !strings.Contains(err.Error(), "--cwe") {
		t.Fatalf("repo mode without --cwe should error clearly, got %v", err)
	}
}

func TestLocalizeCmd_RepoModeLocalizes(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(dir+"/users.go", []byte("func f(r *http.Request){ db.Query(\"SELECT * FROM u WHERE n='\"+r.URL.Query().Get(\"n\")+\"'\") }"), 0o644); err != nil {
		t.Fatal(err)
	}
	out, err := captureStdout(t, func() error {
		return localizeCmd([]string{"--repo", dir, "--cwe", "CWE-89"})
	})
	if err != nil {
		t.Fatalf("localizeCmd repo mode: %v", err)
	}
	if !strings.Contains(out, "users.go") || !strings.Contains(out, "conf=") {
		t.Fatalf("repo-mode output should rank users.go with a confidence:\n%s", out)
	}
}
