package bench

import (
	"os"
	"strings"
	"testing"
)

// TestScorer_NoSUTIdentifiers is the source-grep anti-overfit guard
// (CLAUDE.md §14.2.1). The scoring logic must never hardcode a
// system-under-test identifier — if it did, the scorer could be tuned
// to one fixture's response shape and the recall numbers would be
// meaningless. SUT identifiers belong in fixture DATA (fixture.json),
// never in the scoring CODE.
//
// We scan only the files that compute the metric. fixture.go (loads
// data), runner.go (subprocess plumbing — takes target as a variable),
// and *_test.go (legitimately reference SUTs) are excluded.
func TestScorer_NoSUTIdentifiers(t *testing.T) {
	scoringFiles := []string{"score.go", "report.go", "multitrial.go", "agent.go"}

	forbidden := []string{
		// vulnerable-app SUTs
		"juice-shop", "juiceshop", "bkimminich", "vampi", "crapi",
		"erev0s", "testphp", "vulnweb", "dvwa", "webgoat", "wavsep",
		// per-asset internal-fixture SUT tokens (C6)
		"vulhub", "example.com", "host.docker.internal",
		// fixture target tokens that must not leak into scoring math
		"nginx", "alpine", "cve-2020", "cve-2019",
	}

	for _, file := range scoringFiles {
		data, err := os.ReadFile(file)
		if err != nil {
			t.Fatalf("read %s: %v", file, err)
		}
		lower := strings.ToLower(string(data))
		for _, bad := range forbidden {
			if strings.Contains(lower, bad) {
				t.Errorf("%s contains SUT identifier %q — scoring must be SUT-agnostic (CLAUDE.md §14.2.1)", file, bad)
			}
		}
	}
}

// TestAllFixtures_CiteCompetitors enforces the mandatory-competitor-
// citation guard (CLAUDE.md §14.2.2) across every shipped fixture: each
// must declare a leaderboard or an explicit note. The loader rejects
// non-conforming fixtures, so this also smoke-tests that every fixture
// on disk loads.
func TestAllFixtures_CiteCompetitors(t *testing.T) {
	roots := []string{
		"../../fixtures/container/nginx-vuln",
		"../../fixtures/container/alpine-clean",
		"../../fixtures/web/wavsep",
		"../../fixtures/repo/owasp-benchmark",
		// Per-asset internal must-find fixtures (C6).
		"../../fixtures/api/vampi",
		"../../fixtures/ip/services",
		"../../fixtures/domain/recon",
		"../../fixtures/cloud/baseline",
	}
	for _, r := range roots {
		f, err := Load(r)
		if err != nil {
			t.Errorf("load %s: %v", r, err)
			continue
		}
		if f.Competitors.Leaderboard == "" && f.Competitors.Note == "" {
			t.Errorf("fixture %s has no competitor citation", f.Name)
		}
	}
}
