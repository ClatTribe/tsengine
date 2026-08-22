package prbot

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

// The shipped CI action is the client of this gate, and NOTHING COMPILES IT. It is bash with an
// embedded python heredoc inside YAML — three languages, no type checker, shipped to customers as
// the thing that stops a vulnerable merge.
//
// Every failure mode it had was the same one this package just fixed, reached from the other side:
//
//  1. `git fetch ... || true` swallowed a failed fetch.
//  2. `subprocess.run(capture_output=True)` ignored git's exit code — git exits 128 when the base
//     ref is absent (measured), and capture_output turns that into an empty string that is
//     indistinguishable from "this PR changed nothing".
//  3. `curl` without --fail-with-body left RESP empty on a 500 or an expired token, `.blocked` was
//     not "true", and the action exited 0.
//
// Each produced a green security gate over a pull request nobody looked at. actions/checkout
// defaults to fetch-depth: 1 and the three-dot merge base frequently does not exist on a shallow
// clone, so (1) and (2) were the ordinary case rather than the edge one.
//
// Same reasoning as internal/legalcheck: the guard lives in Go because `go test ./...` runs on every
// PR and nothing else here would run at all.
func TestShippedActionFailsLoudlyWhenItCannotSeeTheDiff(t *testing.T) {
	b, err := os.ReadFile("../../docs/ci/github-action.yml")
	if err != nil {
		t.Fatalf("cannot read the shipped action: %v", err)
	}
	src := string(b)

	required := []struct{ needle, why string }{
		{"if ! git fetch",
			"a fetch that failed means no merge base, so the diff would come back empty and the gate green"},
		{"check=True",
			"git exits 128 when the base ref is absent; without check=True that arrives as an empty diff"},
		{"--fail-with-body",
			"without it a 500 or an expired token leaves the response empty and the action exits 0"},
		{"jq 'length' /tmp/changed.json",
			"a pull request that changes no files does not exist — an empty list is always a broken diff"},
		{"fetch-depth: 0",
			"the header must tell the customer to check out with full history, or every shallow " +
				"checkout silently lands in the case above"},
	}
	for _, r := range required {
		if !strings.Contains(src, r.needle) {
			t.Errorf("the shipped action no longer contains %q.\n\nThat guard is there because %s.\n"+
				"Removing it returns the gate to reporting success on a PR it never inspected.",
				r.needle, r.why)
		}
	}

	// And `|| true` must not come back on the fetch — the original swallow.
	if strings.Contains(src, `git fetch --no-tags --depth=1 origin "$BASE" || true`) {
		t.Error("the fetch swallows its own failure again")
	}
}

// The bash must at least parse. It is shipped, it is not compiled, and a syntax error would surface
// as a broken pipeline in a customer's repo.
func TestShippedActionBashParses(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}
	b, err := os.ReadFile("../../docs/ci/github-action.yml")
	if err != nil {
		t.Fatal(err)
	}
	// The run: block is the YAML block scalar under the single step; take everything after it and
	// strip the uniform indentation. Crude, and adequate: the check is that bash accepts it.
	src := string(b)
	i := strings.Index(src, "      run: |\n")
	if i < 0 {
		t.Fatal("run: block not found — if the action's shape changed, update this guard rather " +
			"than leaving it matching nothing")
	}
	var lines []string
	for _, ln := range strings.Split(src[i+len("      run: |\n"):], "\n") {
		lines = append(lines, strings.TrimPrefix(ln, "        "))
	}
	script := strings.Join(lines, "\n")

	f, err := os.CreateTemp(t.TempDir(), "action-*.sh")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(script); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	if out, err := exec.Command("bash", "-n", f.Name()).CombinedOutput(); err != nil {
		t.Errorf("the shipped action's bash does not parse: %v\n%s", err, out)
	}
}
