// Package legalcheck holds no runtime code — it exists solely to gate the PUBLISHED legal
// documents in CI, the same way §14.2's anti-overfit source-grep tests gate the benches.
//
// Why a Go test for TypeScript files: the frontend has no test runner (its CI job is
// lint + typecheck + build), but `go test ./...` already runs on every PR. Putting the guard
// here means it actually executes, with no new tooling.
//
// What it prevents: the Terms and Privacy pages shipped to production containing literal
// "[legal entity name]" and "[city]". An agreement that never names the contracting party or
// the forum is unenforceable — a correctness defect in a legal document, not a typo.
package legalcheck

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// legalPages are the contract documents. /security is excluded — it is a disclosure page,
// not an agreement.
var legalPages = []string{"terms", "privacy", "dpa", "subprocessors"}

// placeholderRe matches a [bracketed placeholder] of lowercase words — the shape a template
// leaves behind. Deliberately narrow so ordinary bracketed prose does not trip it.
var placeholderRe = regexp.MustCompile(`\[[a-z][a-z ]{2,40}\]`)

func marketingDir(t *testing.T) string {
	t.Helper()
	dir, err := filepath.Abs(filepath.Join("..", "..", "frontend", "app", "(marketing)"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(dir); err != nil {
		t.Skipf("frontend marketing pages not present (%v) — skipping legal guard", err)
	}
	return dir
}

func TestLegalPagesHaveNoUnfilledPlaceholders(t *testing.T) {
	root := marketingDir(t)
	for _, page := range legalPages {
		p := filepath.Join(root, page, "page.tsx")
		b, err := os.ReadFile(p)
		if err != nil {
			t.Errorf("%s: %v", page, err)
			continue
		}
		if m := placeholderRe.FindString(string(b)); m != "" {
			t.Errorf("%s/page.tsx ships an unfilled placeholder %q — set it via frontend/lib/site.ts "+
				"(NEXT_PUBLIC_LEGAL_ENTITY / NEXT_PUBLIC_LEGAL_JURISDICTION_CITY) instead of hardcoding", page, m)
		}
	}
}

// The legally load-bearing strings must come from the single config module, so one deploy-time
// setting fills every document. A page that hardcodes the brand-and-entity phrasing again would
// silently drift from the configured entity.
func TestLegalPagesSourceIdentityFromConfig(t *testing.T) {
	root := marketingDir(t)
	for _, page := range []string{"terms", "privacy"} {
		b, err := os.ReadFile(filepath.Join(root, page, "page.tsx"))
		if err != nil {
			t.Fatalf("%s: %v", page, err)
		}
		if !strings.Contains(string(b), "legalPartyName") {
			t.Errorf("%s/page.tsx must name the contracting party via legalPartyName() from @/lib/site", page)
		}
	}
}

// Adding a new contract page without covering it here would leave it unguarded.
func TestEveryLegalPageIsCovered(t *testing.T) {
	root := marketingDir(t)
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	known := map[string]bool{"security": true} // disclosure page, not a contract
	for _, p := range legalPages {
		known[p] = true
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		name := e.Name()
		// Heuristic: a directory whose page.tsx renders the shared LegalDoc component is a
		// contract document and must be in legalPages.
		b, err := os.ReadFile(filepath.Join(root, name, "page.tsx"))
		if err != nil {
			continue
		}
		if strings.Contains(string(b), "LegalDoc") && !known[name] {
			t.Errorf("marketing page %q renders LegalDoc but is not in legalPages — add it so the placeholder guard covers it", name)
		}
	}
}
