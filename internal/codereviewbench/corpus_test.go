package codereviewbench

import (
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

func repoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "..", "..")
}

// corpusFloor is the case count the corpus must never drop below. A corpus that shrinks still scores —
// often HIGHER, on an easier subset — under the same name, which is the vacuous-pass shape §14.2 warns
// about. Raise it when cases are added; lowering it is a decision someone has to make in review.
const corpusFloor = 26

func TestCorpusLoadsAndDoesNotShrink(t *testing.T) {
	cases, err := Load(filepath.Join(repoRoot(t), "fixtures", "codereview"))
	if err != nil {
		t.Fatalf("the shipped corpus must load (a guard that cannot see its subject fails, §14.2 rule 6): %v", err)
	}
	if len(cases) < corpusFloor {
		t.Fatalf("corpus has %d cases, floor is %d — a smaller corpus scores an easier benchmark under the same name",
			len(cases), corpusFloor)
	}
	for _, c := range cases {
		if !strings.HasPrefix(c.Source, "https://github.com/advisories/") {
			t.Errorf("%s: the answer key must cite the public advisory so it is checkable, got %q", c.ID, c.Source)
		}
		if c.PublishedAt == "" {
			t.Errorf("%s: publication date missing — the contamination question cannot be answered without it", c.ID)
		}
	}
}

// HELD-OUT (§14.2 rules 1 and 5): the reviewers must not know the corpus. A case repository named in a
// reviewer's source is either a tuned special case or a leak of the answer key into the thing being graded.
func TestReviewersDoNotNameCorpusRepositories(t *testing.T) {
	root := repoRoot(t)
	cases, err := Load(filepath.Join(root, "fixtures", "codereview"))
	if err != nil {
		t.Fatal(err)
	}
	var needles []string
	for _, c := range cases {
		needles = append(needles, strings.ToLower(c.Repo))
		if name := strings.ToLower(c.Repo[strings.Index(c.Repo, "/")+1:]); len(name) >= 6 {
			needles = append(needles, name)
		}
	}
	scanned := 0
	for _, dir := range []string{"internal/codesweep", "internal/codelocalize", "internal/tool/deepsec"} {
		_ = filepath.WalkDir(filepath.Join(root, dir), func(p string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(p, ".go") {
				return nil
			}
			b, rerr := os.ReadFile(p)
			if rerr != nil {
				return nil
			}
			scanned++
			src := strings.ToLower(string(b))
			for _, n := range needles {
				// Whole-word: "unknowns" is not the repository "knowns".
				if regexp.MustCompile(`(^|[^a-z0-9])` + regexp.QuoteMeta(n) + `($|[^a-z0-9])`).MatchString(src) {
					t.Errorf("%s names corpus repository %q — the benchmark is no longer held out for this reviewer", p, n)
				}
			}
			return nil
		})
	}
	if scanned < 5 {
		t.Fatalf("scanned only %d reviewer files — the guard is not seeing its subject", scanned)
	}
}
