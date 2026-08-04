package main

import (
	"os"
	"path/filepath"
	"testing"
)

// skillsDir must never silently substitute a different library than the operator asked for — a
// curated skill set is a security-relevant choice, and quietly falling back to a bundled one would
// run reasoning they did not approve.
func TestSkillsDir_ExplicitEnvWins(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("TSENGINE_SKILLS_DIR", dir)
	if got := skillsDir(); got != dir {
		t.Fatalf("skillsDir() = %q, want the configured %q", got, dir)
	}
}

func TestSkillsDir_ConfiguredButUnusableDisablesRatherThanFallsBack(t *testing.T) {
	// Point at a path that does not exist, from a working directory that DOES have ./skills.
	// The bundled library must not be silently used in its place.
	wd := t.TempDir()
	if err := os.Mkdir(filepath.Join(wd, "skills"), 0o755); err != nil {
		t.Fatal(err)
	}
	chdir(t, wd)
	t.Setenv("TSENGINE_SKILLS_DIR", filepath.Join(wd, "nope"))

	if got := skillsDir(); got != "" {
		t.Fatalf("a misconfigured TSENGINE_SKILLS_DIR must disable skills, not fall back to %q", got)
	}
}

func TestSkillsDir_FallsBackToBundledOnlyWhenUnset(t *testing.T) {
	wd := t.TempDir()
	if err := os.Mkdir(filepath.Join(wd, "skills"), 0o755); err != nil {
		t.Fatal(err)
	}
	chdir(t, wd)
	t.Setenv("TSENGINE_SKILLS_DIR", "")

	if got := skillsDir(); got != "skills" {
		t.Fatalf("skillsDir() = %q, want the bundled ./skills", got)
	}
}

func TestSkillsDir_EmptyWhenNothingAvailable(t *testing.T) {
	chdir(t, t.TempDir()) // no ./skills here
	t.Setenv("TSENGINE_SKILLS_DIR", "")
	if got := skillsDir(); got != "" {
		t.Fatalf("with no library available skillsDir() should be empty, got %q — the platform must not guess a path", got)
	}
}

// A file (not a directory) at the configured path must be refused too.
func TestSkillsDir_RejectsAFile(t *testing.T) {
	f := filepath.Join(t.TempDir(), "skills.txt")
	if err := os.WriteFile(f, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TSENGINE_SKILLS_DIR", f)
	if got := skillsDir(); got != "" {
		t.Fatalf("a file is not a skill library; got %q", got)
	}
}

func chdir(t *testing.T, dir string) {
	t.Helper()
	prev, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(prev) })
}
