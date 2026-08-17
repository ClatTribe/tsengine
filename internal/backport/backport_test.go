package backport

import (
	"strings"
	"testing"
)

func lines(s string) []string { return strings.Split(strings.TrimPrefix(s, "\n"), "\n") }

// The vulnerable file, as it appears on an older release branch where the code
// ABOVE the bug has diverged (extra imports/helpers) so the fix's line number
// no longer matches.
const olderBranch = `
package main

import (
	"fmt"
	"os/exec"
)

func helperAddedOnThisBranch() {}

func run(userInput string) {
	cmd := exec.Command("sh", "-c", userInput)
	cmd.Run()
}
`

// The security fix as written against main: stop shelling out with user input.
func fixHunk() Hunk {
	return Hunk{
		File:      "main.go",
		StartLine: 9, // where it applied on main — only a hint
		Before:    []string{"func run(userInput string) {"},
		Removed:   []string{"\tcmd := exec.Command(\"sh\", \"-c\", userInput)"},
		Added:     []string{"\tcmd := exec.Command(\"echo\", userInput) // no shell interpretation"},
		After:     []string{"\tcmd.Run()"},
	}
}

// The headline case: the fix's claimed line is wrong on this branch, but the
// context locates it — an OFFSET application, which is mechanically safe.
func TestLocate_OffsetWhenCodeAboveDiverged(t *testing.T) {
	got := Locate(lines(olderBranch), fixHunk())
	if got.Verdict != VerdictOffset {
		t.Fatalf("verdict = %q (%s), want offset", got.Verdict, got.Reason)
	}
	if got.Offset == 0 {
		t.Error("an offset match should report a non-zero offset")
	}
	// And it applies, producing a file that contains the fix and not the bug.
	out, ok := Apply(lines(olderBranch), fixHunk(), got)
	if !ok {
		t.Fatal("an offset verdict must be applicable")
	}
	joined := strings.Join(out, "\n")
	if strings.Contains(joined, `"sh", "-c"`) {
		t.Error("the vulnerable line should be gone")
	}
	if !strings.Contains(joined, "no shell interpretation") {
		t.Error("the fix should be present")
	}
}

// Double-applying a security patch is a real, damaging failure mode. An
// already-fixed branch must be reported, never patched again.
func TestLocate_AlreadyAppliedIsDetectedAndRefused(t *testing.T) {
	fixed := lines(olderBranch)
	r := Locate(fixed, fixHunk())
	out, _ := Apply(fixed, fixHunk(), r)

	second := Locate(out, fixHunk())
	if second.Verdict != VerdictAlreadyApplied {
		t.Fatalf("verdict = %q (%s), want already_applied", second.Verdict, second.Reason)
	}
	if _, ok := Apply(out, fixHunk(), second); ok {
		t.Error("an already-applied fix must NOT be applicable a second time")
	}
}

// A branch that never had the vulnerable code path: backporting is not
// meaningful, and we say so instead of forcing something in.
func TestLocate_NotApplicableWhenCodeAbsent(t *testing.T) {
	other := lines(`
package main

func run(userInput string) {
	println(userInput)
}
`)
	got := Locate(other, fixHunk())
	if got.Verdict != VerdictNotApplicable {
		t.Fatalf("verdict = %q (%s), want not_applicable", got.Verdict, got.Reason)
	}
	if _, ok := Apply(other, fixHunk(), got); ok {
		t.Error("a not-applicable hunk must never apply")
	}
}

// Formatting drift is recognisable but NOT safe to apply mechanically — the
// deterministic layer refuses and escalates to adaptation (where an LLM may
// propose, and Apply still gates the result).
func TestLocate_FormattingDriftNeedsAdaptation(t *testing.T) {
	reformatted := lines(`
package main

func run(userInput string) {
	cmd  :=  exec.Command( "sh" , "-c" , userInput )
	cmd.Run()
}
`)
	got := Locate(reformatted, fixHunk())
	if got.Verdict != VerdictNeedsAdaptation {
		t.Fatalf("verdict = %q (%s), want needs_adaptation", got.Verdict, got.Reason)
	}
	if _, ok := Apply(reformatted, fixHunk(), got); ok {
		t.Error("needs_adaptation must not auto-apply")
	}
}

// Ambiguity: the vulnerable line appears twice. Without disambiguating context
// we must not pick one — that is a coin flip on a security patch.
func TestLocate_AmbiguousSiteNeedsAdaptation(t *testing.T) {
	twice := lines(`
package main

func a(userInput string) {
	cmd := exec.Command("sh", "-c", userInput)
	cmd.Run()
}

func b(userInput string) {
	cmd := exec.Command("sh", "-c", userInput)
	cmd.Run()
}
`)
	h := fixHunk()
	h.Before = nil // no disambiguating context
	h.After = nil
	got := Locate(twice, h)
	if got.Verdict != VerdictNeedsAdaptation {
		t.Fatalf("verdict = %q (%s), want needs_adaptation for an ambiguous site", got.Verdict, got.Reason)
	}
}

// With context supplied, the SAME ambiguous file resolves to the right site.
func TestLocate_ContextDisambiguatesAmbiguousSite(t *testing.T) {
	twice := lines(`
package main

func a(userInput string) {
	cmd := exec.Command("sh", "-c", userInput)
	cmd.Run()
}

func b(userInput string) {
	cmd := exec.Command("sh", "-c", userInput)
	cmd.Run()
}
`)
	h := fixHunk()
	h.Before = []string{"func b(userInput string) {"} // target the SECOND one
	h.StartLine = 0
	got := Locate(twice, h)
	if got.Verdict != VerdictClean && got.Verdict != VerdictOffset {
		t.Fatalf("verdict = %q (%s), want an applicable match", got.Verdict, got.Reason)
	}
	out, ok := Apply(twice, h, got)
	if !ok {
		t.Fatal("should apply")
	}
	// func a must be untouched; func b fixed.
	joined := strings.Join(out, "\n")
	if strings.Count(joined, `"sh", "-c"`) != 1 {
		t.Errorf("exactly one vulnerable call should remain (func a), got:\n%s", joined)
	}
	idxFix := strings.Index(joined, "no shell interpretation")
	idxB := strings.Index(joined, "func b(")
	if idxFix < idxB {
		t.Error("the fix should have landed inside func b, not func a")
	}
}

// A pure insertion (e.g. adding a missing bounds check) anchors on context.
func TestLocate_PureInsertionAnchorsOnContext(t *testing.T) {
	target := lines(`
package main

func get(i int, xs []int) int {
	return xs[i]
}
`)
	h := Hunk{
		File:    "main.go",
		Before:  []string{"func get(i int, xs []int) int {"},
		Added:   []string{"\tif i < 0 || i >= len(xs) { return 0 }"},
		Removed: nil,
	}
	got := Locate(target, h)
	if got.Verdict != VerdictClean && got.Verdict != VerdictOffset {
		t.Fatalf("verdict = %q (%s), want an applicable insertion", got.Verdict, got.Reason)
	}
	out, ok := Apply(target, h, got)
	if !ok {
		t.Fatal("insertion should apply")
	}
	if !strings.Contains(strings.Join(out, "\n"), "i >= len(xs)") {
		t.Error("the bounds check should be inserted")
	}
}

func TestLocate_EmptyHunkIsNotApplicable(t *testing.T) {
	if got := Locate(lines(olderBranch), Hunk{File: "main.go"}); got.Verdict != VerdictNotApplicable {
		t.Errorf("an empty hunk should be not_applicable, got %q", got.Verdict)
	}
}

// Every verdict carries a reason — the audit trail for why a security backport
// was applied, skipped, or escalated.
func TestLocate_AlwaysExplainsItself(t *testing.T) {
	for name, r := range map[string]Result{
		"offset":    Locate(lines(olderBranch), fixHunk()),
		"absent":    Locate(lines("package main"), fixHunk()),
		"emptyHunk": Locate(lines(olderBranch), Hunk{}),
	} {
		if strings.TrimSpace(r.Reason) == "" {
			t.Errorf("%s: verdict %q must carry a reason", name, r.Verdict)
		}
	}
}
