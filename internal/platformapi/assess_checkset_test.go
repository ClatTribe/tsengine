package platformapi

import (
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/ClatTribe/tsengine/internal/operate"
	"testing"
)

// The set of checks GET /v1/assess runs is DESCRIBED IN PROSE on surfaces that cannot be
// type-checked against it, so this test pins the set and names them.
//
// Why it exists (ADR 0023 decision 6). A blog post listed five checks and said the free
// scanner "runs exactly these". It ran four. The fifth — known vulnerabilities in shipped
// dependencies — needs a connected repository and is not visible from a domain name at all.
// That is not a marketing overstatement; it fails in the direction the whole engine exists to
// prevent. A founder runs the scan, sees a grade with no dependency finding in it, and
// concludes their dependencies are clean. It is the same defect class as a scanner rendering
// a check that did not run as one that passed (§10, asset.CoverageRulePrefix) — arriving
// through copy instead of through a tool.
//
// Prose cannot be verified against behaviour. What CAN be pinned is the set itself, so that
// adding or removing a check fails here with a message naming every surface a human then has
// to go and update. This is the same "pin the one line that decides" shape used on the
// threat-intel path.
//
// IF THIS TEST FAILS: the check set changed. Update the list below AND every surface named in
// describedOn — the test is the reminder, not the enforcement.
var assessCheckSet = []string{
	"Clickjacking & MIME protections",
	"Content-Security-Policy",
	"DKIM",
	"DMARC enforcement",
	"HSTS",
	"HTTPS enforced",
	"SPF",
	"Security contact (security.txt)",
}

// The surfaces that describe the check set to a customer in words. Each is a repo-relative
// path plus the phrase that pins the count, so a stale description is greppable rather than
// hypothetical.
var describedOn = []struct {
	path   string
	phrase string
}{
	{"frontend/lib/blog.ts", "runs eight read-only checks"},
}

func TestAssessCheckSetIsPinned(t *testing.T) {
	// The email checks come from assess.go and the web checks from assess_web.go. Building
	// the union from the real handlers rather than restating it is the point: a check added
	// to either file lands here without anyone remembering to update a second list.
	got := assessEmailCheckNames()
	got = append(got, assessWebCheckNames()...)
	sort.Strings(got)

	want := append([]string(nil), assessCheckSet...)
	sort.Strings(want)

	if len(got) != len(want) {
		t.Fatalf("the /v1/assess check set changed: %d checks, pinned set has %d.\n got:  %v\n want: %v\n\n"+
			"Update assessCheckSet AND the customer-facing copy that states the count: %v",
			len(got), len(want), got, want, describedOn)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("the /v1/assess check set changed at %d: got %q, pinned %q.\n\n"+
				"Update assessCheckSet AND the copy that describes it: %v", i, got[i], want[i], describedOn)
		}
	}
}

// TestAssessCheckCountIsStatedCorrectly reads the customer-facing copy and asserts it still
// states the real number. It is deliberately crude — it looks for one exact phrase — because a
// crude check that fails loudly beats a clever one that tries to parse marketing prose and
// quietly decides everything is fine.
func TestAssessCheckCountIsStatedCorrectly(t *testing.T) {
	root, err := repoRoot()
	if err != nil {
		t.Fatalf("locating repo root: %v", err) // never skip: a guard that excuses itself reports green forever
	}
	for _, d := range describedOn {
		b, err := os.ReadFile(filepath.Join(root, d.path))
		if err != nil {
			t.Fatalf("reading %s: %v (if this file moved, update describedOn)", d.path, err)
		}
		if !strings.Contains(string(b), d.phrase) {
			t.Errorf("%s no longer contains %q.\n"+
				"The /v1/assess check set has %d checks. Either the copy drifted from the code or the "+
				"phrase was reworded — fix whichever is wrong, then update describedOn.",
				d.path, d.phrase, len(assessCheckSet))
		}
	}
}

// The two name lists are DERIVED by running the real check builders, not restated. A check
// added to either file therefore lands in this test on its own, and the pinned set above is
// the only thing a human has to update — which is the whole point, since the failure this
// guards against is exactly a second list drifting from the first.
//
// Both builders are called with the minimum input that makes them emit their FULL set, and
// both gate on "could we actually look":
//
//   - assessEmailAuth skips a check whose DNS lookup was Unresolved, so a zero DomainConfig
//     (empty Unresolved) yields all three.
//   - assessWeb returns NOTHING at all unless wp.Reachable — an unreachable site must not
//     report failing checks nobody ran.
//
// The Reachable flag is load-bearing and was got wrong on the first draft of this test, which
// then reported 3 checks instead of 8. Worth stating rather than leaving as a bare literal:
// the same honesty rule that shapes the handler shapes how you have to call it.
func assessEmailCheckNames() []string {
	var names []string
	for _, c := range assessEmailAuth(operate.DomainConfig{Name: "example.com"}).Checks {
		names = append(names, c.Name)
	}
	return names
}

func assessWebCheckNames() []string {
	checks, _, _ := assessWeb(webPosture{Reachable: true})
	var names []string
	for _, c := range checks {
		names = append(names, c.Name)
	}
	return names
}

// repoRoot walks up from the working directory to the directory holding go.mod. It returns an
// error rather than falling back to a guess, so a layout change surfaces as a failure instead
// of as a test that silently checks nothing.
func repoRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", os.ErrNotExist
		}
		dir = parent
	}
}
