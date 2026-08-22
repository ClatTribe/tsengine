package claimcheck

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// repoRoot walks up to the module root so the guard reads the real documents rather than a fixture.
// A fixture cannot catch this class of bug: the failure IS the shipped document disagreeing with the
// shipped code.
func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("cwd: %v", err)
	}
	for i := 0; i < 8; i++ {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		dir = filepath.Dir(dir)
	}
	t.Fatal("could not locate the module root: this guard cannot see its subject")
	return ""
}

func readDocs(t *testing.T) map[string]string {
	t.Helper()
	root := repoRoot(t)
	out := map[string]string{}
	for _, d := range Docs {
		b, err := os.ReadFile(filepath.Join(root, d))
		if err != nil {
			// FAIL, never skip. A renamed or deleted document is exactly when this guard stops
			// guarding, and a skip is green (§14.2 rule 6).
			t.Fatalf("scanned document %s is unreadable (%v). If it moved, update claimcheck.Docs — "+
				"a claims guard that silently stops reading a document is worse than none.", d, err)
		}
		out[d] = string(b)
	}
	return out
}

// THE property: a recomputable headline number must still compute to the value we publish. Before
// this, the code could drift under the claim and nothing failed.
func TestClaims_RecomputableOnesStillHoldTheirPublishedValue(t *testing.T) {
	n := 0
	for _, c := range Registry() {
		if c.Recompute == nil {
			continue
		}
		n++
		got := fmt.Sprintf(c.Format, c.Recompute())
		if got != c.Value {
			t.Errorf("%s: recomputes to %s but we publish %s.\n"+
				"If the product improved, update Claim.Value AND every document that states it — "+
				"a number that rises while the docs quote the old one is how three documents came to "+
				"disagree about the same metric.", c.Name, got, c.Value)
		}
	}
	if n == 0 {
		t.Fatal("no claim in the registry is recomputable: this guard is asserting nothing")
	}
}

// Every claim must be traceable and stated where it belongs.
func TestClaims_EveryClaimHasProvenanceAndIsStatedInItsHomeDocument(t *testing.T) {
	docs := readDocs(t)
	reg := Registry()
	if len(reg) == 0 {
		t.Fatal("the claims registry is empty: this guard cannot see its subject")
	}
	for _, c := range reg {
		if strings.TrimSpace(c.Source) == "" {
			t.Errorf("%s: no Source. A headline number with no provenance is an assertion, not a measurement.", c.Name)
		}
		if strings.TrimSpace(c.Home) == "" {
			t.Errorf("%s: no Home document", c.Name)
			continue
		}
		body, ok := docs[c.Home]
		if !ok {
			t.Errorf("%s: Home %q is not in claimcheck.Docs, so it is never scanned", c.Name, c.Home)
			continue
		}
		if !strings.Contains(body, c.Value) {
			t.Errorf("%s: %s does not state the published value %q. Either the document dropped the "+
				"claim or the claim changed without the document following.", c.Name, c.Home, c.Value)
		}
	}
}

// THE bug this package was written for: a metric improves in the code and an old value keeps being
// quoted somewhere else. ADR 0024 had to record that CLAUDE.md's 0.753 and the roadmap's 0.322 for
// the SAME metric were both stale.
func TestClaims_NoDocumentQuotesASupersededValue(t *testing.T) {
	docs := readDocs(t)
	checked := 0
	for _, c := range Registry() {
		for _, old := range c.Superseded {
			checked++
			for name, body := range docs {
				for _, at := range indexAll(body, old) {
					// Quoting an earlier value is legitimate when the passage carries the trajectory
					// through to the CURRENT one ("0.322 → 0.753 → 0.993"), or when it names the old
					// value in order to correct it. What is not legitimate is a superseded number
					// standing alone, because a reader skimming has no way to tell it is dead. So the
					// rule is proximity to the current value, not absence.
					if nearby(body, at, c.Value, claimWindow) {
						continue
					}
					t.Errorf("%s quotes %s for %s with no mention of the current %s nearby.\n"+
						"Either bring the trajectory up to date (0.322 → 0.753 → %s) or drop the old "+
						"value — a superseded number standing alone is one a reader cannot tell is dead.",
						name, old, c.Name, c.Value, c.Value)
				}
			}
		}
	}
	if checked == 0 {
		t.Fatal("no superseded value is declared anywhere in the registry: this guard is asserting " +
			"nothing. If a metric has genuinely never moved, that is worth stating explicitly rather " +
			"than leaving the guard vacuous.")
	}
}

// claimWindow is how far either side of a superseded value we look for the current one. Wide enough
// to span a wrapped markdown paragraph, narrow enough that an unrelated mention elsewhere in the
// document does not launder a stale number.
const claimWindow = 400

func indexAll(body, sub string) []int {
	var out []int
	for i := 0; ; {
		j := strings.Index(body[i:], sub)
		if j < 0 {
			return out
		}
		out = append(out, i+j)
		i += j + len(sub)
	}
}

// nearby reports whether want appears within win characters either side of position at.
func nearby(body string, at int, want string, win int) bool {
	lo, hi := at-win, at+win
	if lo < 0 {
		lo = 0
	}
	if hi > len(body) {
		hi = len(body)
	}
	return strings.Contains(body[lo:hi], want)
}
