package archcheck

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestReadEnv_MatchesComposeSemantics guards scripts/read-env.sh, which the Makefile's image builds
// use to load .env.
//
// The bug it exists to prevent was found by running it, not reading it. The obvious implementation
// is `. ./.env`, which EVALUATES the file as shell — so
//
//	NEXT_PUBLIC_LEGAL_ENTITY=Acme Security Pvt Ltd
//
// sets the entity to "Acme", tries to run `Security` as a command, and leaves the variable empty.
// The frontend then publishes legal pages with no contracting entity, which is the exact failure
// passing these build args is meant to prevent. docker compose does not shell-evaluate an env file,
// so the SAME .env worked under compose and broke under make — two halves of one product disagreeing
// about one input, which is worse than either of them simply failing.
func TestReadEnv_MatchesComposeSemantics(t *testing.T) {
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(root, "scripts", "read-env.sh")
	if _, err := os.Stat(script); err != nil {
		t.Fatalf("read-env.sh is missing (%v). The Makefile sources it for every image build; if it "+
			"moved, move this guard with it rather than letting the check stop seeing its subject.", err)
	}

	dir := t.TempDir()
	envFile := filepath.Join(dir, ".env")
	const content = `# a comment

SPACED=Acme Security Pvt Ltd
DQUOTED="hi@acme.io"
SQUOTED='12 MG Road, Bengaluru'
DSN=postgres://u:p@host:5432/db?sslmode=require
EXPORTED=plain
NOT_AN_ASSIGNMENT
`
	if err := os.WriteFile(envFile, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	// TS_ENV_FILE, not a positional arg: POSIX `.` takes no arguments, and /bin/sh is dash on CI.
	// Passing the path as $1 worked on macOS and silently read nothing on Ubuntu — this test failed
	// in CI having passed locally, which is exactly the platform gap it should have been written for.
	out, err := exec.Command("sh", "-c",
		"TS_ENV_FILE="+envFile+" . "+script+`; printf '%s\n%s\n%s\n%s\n%s\n' "$SPACED" "$DQUOTED" "$SQUOTED" "$DSN" "$EXPORTED"`).CombinedOutput()
	if err != nil {
		t.Fatalf("read-env.sh failed: %v\n%s", err, out)
	}
	got := strings.Split(strings.TrimRight(string(out), "\n"), "\n")

	want := []string{
		"Acme Security Pvt Ltd",                       // the one that used to silently become "Acme"
		"hi@acme.io",                                  // one layer of double quotes stripped
		"12 MG Road, Bengaluru",                       // single quotes, and a comma
		"postgres://u:p@host:5432/db?sslmode=require", // '=' inside the value survives
		"plain",
	}
	if len(got) != len(want) {
		t.Fatalf("got %d values, want %d:\n%q", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("value %d = %q, want %q", i, got[i], want[i])
		}
	}
}

// TestReadEnv_AbsentFileIsNotAnError: the image build must work on a clean checkout with no .env,
// falling back to the defaults in the Makefile rather than dying.
func TestReadEnv_AbsentFileIsNotAnError(t *testing.T) {
	root, _ := filepath.Abs("../..")
	script := filepath.Join(root, "scripts", "read-env.sh")
	out, err := exec.Command("sh", "-c",
		"TS_ENV_FILE="+filepath.Join(t.TempDir(), "nope.env")+" . "+script+`; echo ALIVE`).CombinedOutput()
	if err != nil {
		t.Fatalf("a missing .env aborted the build: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "ALIVE") {
		t.Errorf("execution did not continue past a missing .env: %q", out)
	}
}
