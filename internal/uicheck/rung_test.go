package uicheck

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// rung_test.go guards the READER half of ADR 0029 D2d.
//
// CLAUDE.md §11 already names this failure by shape: "a new L1.5 signal gets wired to the agent
// because that is where the author is working, and the human surface is a separate file nobody opens
// — so ASSUME the reader half is missing until checked." The evidence rung was heading the same way.
// The engine computes it, the L1.5 chain stamps it and the VAPT report prints it, while the finding
// page — the flagship surface, the one a security engineer actually opens — rendered the raw
// three-value verification word as a bare tag.
//
// That word is exactly what could not carry the distinction: "verified" on a web finding means an
// exploit ran; on a cloud path it means the provider's simulator authorized it. Same tag, same
// colour, two different claims.

func findingPageSource(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", "..", "frontend"))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "app", "(app)", "findings", "[id]", "page.tsx")
	src, err := os.ReadFile(path)
	if err != nil {
		// Deliberately NOT a skip. A guard that cannot see its subject reporting success is the
		// §14.2 rule 6 failure, and this one exists precisely because the surface it watches is the
		// one nobody remembers to open.
		t.Fatalf("read the finding page (%s): %v — if it moved, move this guard with it", path, err)
	}
	return string(src)
}

func TestFindingPageRendersTheRungNotTheRawVerificationWord(t *testing.T) {
	src := findingPageSource(t)

	if !strings.Contains(src, "f.rung") {
		t.Error("the finding page never reads f.rung. The engine computes how a finding was " +
			"established and the page shows the reader a three-value word that cannot express it " +
			"(ADR 0029 D2d).")
	}
	if !strings.Contains(src, "RUNG_SHORT") {
		t.Error("the page does not render a rung label. Printing the raw id would put our enum in " +
			"front of a customer instead of the claim.")
	}
	if !strings.Contains(src, "RUNG_TOOLTIP") {
		t.Error("the page renders a rung with no tooltip. The badge carries the claim and the tooltip " +
			"carries its LIMIT — 'provider-confirmed' without 'authorization, not exploitation' is the " +
			"overclaim in shorter form.")
	}
	// The fallback must survive: findings stored before the field existed have no rung, and showing
	// nothing at all would be worse than showing the old word.
	if !strings.Contains(src, "f.verification_status") {
		t.Error("the pre-rung fallback was removed. A finding stored before this field existed would " +
			"then render no evidence signal at all, which reads as 'nothing to say' rather than 'older " +
			"record'.")
	}
}

func TestRungBadgeCoversEveryRung(t *testing.T) {
	// A missing entry renders `undefined` in a badge beside a severity chip. Object literals keyed by
	// a union type are checked by tsc, but only while the map stays a literal — this asserts the
	// property directly so a refactor to a computed map cannot lose it silently.
	root, err := filepath.Abs(filepath.Join("..", "..", "frontend"))
	if err != nil {
		t.Fatal(err)
	}
	src, err := os.ReadFile(filepath.Join(root, "lib", "evidence-rungs.ts"))
	if err != nil {
		t.Fatalf("read the rung ladder: %v", err)
	}
	body := string(src)

	i := strings.Index(body, "RUNG_SHORT")
	if i < 0 {
		t.Fatal("RUNG_SHORT is gone from the ladder — the finding page imports it")
	}
	shortBlock := body[i:]
	if end := strings.Index(shortBlock, "};"); end > 0 {
		shortBlock = shortBlock[:end]
	}
	for _, id := range []string{
		"exploited", "provider_confirmed", "reachability_confirmed", "corroborated", "scanner_reported",
	} {
		if !strings.Contains(shortBlock, id+":") {
			t.Errorf("RUNG_SHORT has no label for %q — that rung would render as undefined in the badge", id)
		}
	}
}
