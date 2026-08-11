package codeagent

import (
	"strings"
	"testing"
)

func TestUnifiedDiff_ShowsOnlyTheChangedLines(t *testing.T) {
	before := map[string]string{"internal/store/users.go": strings.Join([]string{
		"package store", "", "import \"database/sql\"", "",
		"func Find(db *sql.DB, name string) {",
		"\tdb.Query(\"SELECT * FROM users WHERE name='\" + name + \"'\")",
		"}", "",
	}, "\n")}
	p := Patch{Files: []PatchedFile{{Path: "internal/store/users.go", Content: strings.Join([]string{
		"package store", "", "import \"database/sql\"", "",
		"func Find(db *sql.DB, name string) {",
		"\tdb.Query(\"SELECT * FROM users WHERE name = ?\", name)",
		"}", "",
	}, "\n")}}}

	got := p.UnifiedDiff(before)

	if !strings.Contains(got, "--- a/internal/store/users.go") || !strings.Contains(got, "+++ b/internal/store/users.go") {
		t.Errorf("missing file header:\n%s", got)
	}
	if !strings.Contains(got, "-\tdb.Query(\"SELECT * FROM users WHERE name='\" + name + \"'\")") {
		t.Errorf("the vulnerable line should be shown as removed:\n%s", got)
	}
	if !strings.Contains(got, "+\tdb.Query(\"SELECT * FROM users WHERE name = ?\", name)") {
		t.Errorf("the fixed line should be shown as added:\n%s", got)
	}
	// The whole point: the reviewer sees the change, not the file. Unchanged lines beyond the
	// context window must not appear.
	if strings.Count(got, "\n") > 14 {
		t.Errorf("diff is too large for a one-line change — context window not applied:\n%s", got)
	}
}

// A patch that changes nothing must render nothing — an empty review is a signal, not a blank page.
func TestUnifiedDiff_NoChangeRendersEmpty(t *testing.T) {
	same := "package x\nfunc F() {}\n"
	p := Patch{Files: []PatchedFile{{Path: "a.go", Content: same}}}
	if got := p.UnifiedDiff(map[string]string{"a.go": same}); got != "" {
		t.Errorf("identical content should render no diff, got:\n%s", got)
	}
}

// A file we have no prior version of is rendered as all-added rather than silently skipped — the
// honest rendering when we genuinely do not know the before state.
func TestUnifiedDiff_NewFileIsAllAdditions(t *testing.T) {
	p := Patch{Files: []PatchedFile{{Path: "new.go", Content: "package x\nfunc New() {}\n"}}}
	got := p.UnifiedDiff(nil)
	if !strings.Contains(got, "+package x") || !strings.Contains(got, "+func New() {}") {
		t.Errorf("new file should render as additions:\n%s", got)
	}
	if strings.Contains(got, "-package") {
		t.Errorf("new file should have no deletions:\n%s", got)
	}
}

// The renderer must never be able to change what gets applied — it only reads.
func TestUnifiedDiff_DoesNotMutatePatch(t *testing.T) {
	p := Patch{Files: []PatchedFile{{Path: "a.go", Content: "package x\nfunc F() {}\n"}}}
	orig := p.Files[0].Content
	_ = p.UnifiedDiff(map[string]string{"a.go": "package x\n"})
	if p.Files[0].Content != orig {
		t.Error("UnifiedDiff mutated the patch — the apply path must be untouched by rendering")
	}
}

func TestUnifiedDiff_TruncatesRunawayRewrites(t *testing.T) {
	var oldLines, newLines []string
	for i := 0; i < 600; i++ {
		oldLines = append(oldLines, "old line")
		newLines = append(newLines, "new line")
	}
	p := Patch{Files: []PatchedFile{{Path: "big.go", Content: strings.Join(newLines, "\n")}}}
	got := p.UnifiedDiff(map[string]string{"big.go": strings.Join(oldLines, "\n")})
	if !strings.Contains(got, "truncated") {
		t.Errorf("a 1200-line rewrite should be truncated with an explicit notice, got %d lines", strings.Count(got, "\n"))
	}
}
