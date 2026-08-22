package archcheck

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Every /v1/ route the LIVING documents name must actually be registered.
//
// Swept 2026-08-22: 125 routes claimed across the docs, and all of them exist. This test keeps that
// true, because a documented endpoint that does not exist is the same defect class as the threat-intel
// feed arch.md invented — an operator follows the guide, the call 404s, and they cannot tell a typo
// from a capability we never shipped.
//
// SCOPE: living documents only. ADRs and docs/design/* are deliberately EXCLUDED: an ADR records a
// decision at a point in time, so a route it names that no longer exists is the historical record
// being accurate, not a defect, and "fixing" one would falsify it. (The same sweep found 12 stale
// CODE paths, all of them in exactly those historical documents.)
func TestLivingDocsOnlyNameRealRoutes(t *testing.T) {
	repo := filepath.Join("..", "..")
	living := []string{"CLAUDE.md", "arch.md", "README.md", filepath.Join("docs", "platform-operations.md")}

	registered := map[string]bool{}
	routeDecl := regexp.MustCompile(`(?:HandleFunc|Handle)\(\s*"(?:(?:GET|POST|PUT|DELETE|PATCH)\s+)?(/[A-Za-z0-9_/{}.-]+)"`)
	for _, dir := range []string{"internal/platformapi", "cmd/platform", "internal/server"} {
		entries, err := os.ReadDir(filepath.Join(repo, dir))
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
				continue
			}
			src, rerr := os.ReadFile(filepath.Join(repo, dir, e.Name()))
			if rerr != nil {
				continue
			}
			for _, m := range routeDecl.FindAllStringSubmatch(string(src), -1) {
				registered[normalizeRoute(m[1])] = true
			}
		}
	}
	if len(registered) < 50 {
		t.Fatalf("only %d routes parsed from the server — the parser broke, not the docs", len(registered))
	}

	// The METHOD is usually inside the backticks (`GET /v1/coverage`), which the first version of
	// this pattern did not allow — so it matched almost nothing and passed vacuously. Caught by
	// mutation-testing the guard itself, which is the only way that failure mode is visible.
	checked := 0
	claim := regexp.MustCompile("`(?:(?:GET|POST|PUT|DELETE|PATCH)\\s+)?(/v1/[A-Za-z0-9_/{}-]+)`")
	for _, doc := range living {
		src, err := os.ReadFile(filepath.Join(repo, doc))
		if err != nil {
			// NOT a continue. These four documents are named explicitly, so a read failure means one
			// was renamed or removed — and then it silently stops being checked while the test stays
			// green, because the other three clear the count floor on their own. Verified: deleting
			// docs/platform-operations.md, the operator guide, left this passing.
			//
			// §14.2 rule 6, in the guard written to enforce it. If a document moves, update this
			// list; do not let the check quietly narrow.
			t.Fatalf("cannot read the living document %s (%v) — it was renamed or removed, and a "+
				"guard that quietly stops checking one of its subjects is worse than no guard", doc, err)
		}
		seen := map[string]bool{}
		for _, m := range claim.FindAllStringSubmatch(string(src), -1) {
			r := normalizeRoute(strings.TrimRight(m[1], "/"))
			// Prose like `/v1/auth/{signup,login,invite}` is a set, not a route; brace-expansion and
			// ellipses are documentation shorthand rather than a path anyone can call.
			if seen[r] || strings.Contains(r, ",") || strings.Contains(r, "...") {
				continue
			}
			seen[r] = true
			checked++
			if !registered[r] {
				t.Errorf("%s names %q and no handler is registered for it — an operator following "+
					"this guide gets a 404 and cannot tell a typo from a capability we never shipped",
					doc, m[1])
			}
		}
	}

	// A guard that matches nothing passes. This one did exactly that in its first version, so the
	// vacuity is now loud rather than green.
	if checked < 40 {
		t.Fatalf("only %d routes matched across the living docs — the pattern is not finding them, "+
			"so a passing result would mean nothing", checked)
	}
}

// normalizeRoute collapses path parameters so `/v1/assets/{id}` and `/v1/assets/{asset_id}` compare
// equal — the docs and the mux do not always choose the same parameter name, and that difference is
// not a defect.
func normalizeRoute(p string) string {
	return regexp.MustCompile(`\{[^}]*\}`).ReplaceAllString(strings.TrimRight(p, "/"), "{}")
}
