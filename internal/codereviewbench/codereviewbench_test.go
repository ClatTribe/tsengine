package codereviewbench

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestChangedOldRanges(t *testing.T) {
	patch := "@@ -10,6 +10,7 @@ func x() {\n" +
		" a\n" + // 10
		" b\n" + // 11
		"-c\n" + // 12 removed
		"+C\n" +
		" d\n" + // 13
		"+inserted\n" + // inserted before 14 → anchor 13
		" e\n" + // 14
		" f\n" + // 15
		"@@ -40,2 +41,2 @@\n" +
		"-old\n" + // 40
		"+new\n" +
		" tail\n"
	got := changedOldRanges("a.go", patch)
	want := []Range{{"a.go", 12, 13}, {"a.go", 40, 40}}
	if len(got) != len(want) {
		t.Fatalf("got %+v want %+v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %+v want %+v", got, want)
		}
	}
}

func TestIsSource(t *testing.T) {
	for p, want := range map[string]bool{
		"src/api/users.ts": true, "pkg/db.go": true, "app/views.py": true,
		"src/api/users.test.ts": false, "pkg/db_test.go": false, "tests/test_views.py": false,
		"README.md": false, "package-lock.json": false, "docs/guide.py": false, "CHANGELOG.md": false,
	} {
		if isSource(p) != want {
			t.Errorf("isSource(%q) = %v", p, !want)
		}
	}
}

func fakeFetch(m map[string]any) Fetch {
	return func(_ context.Context, p string) ([]byte, error) {
		v, ok := m[p]
		if !ok {
			return nil, errors.New("404 " + p)
		}
		return json.Marshal(v)
	}
}

func adv(refs ...string) map[string]any {
	return map[string]any{"ghsa_id": "GHSA-aaaa-bbbb-cccc", "html_url": "https://github.com/advisories/GHSA-aaaa-bbbb-cccc",
		"summary": "SQL injection", "severity": "high", "published_at": "2026-09-23T00:00:00Z",
		"references": refs, "cwes": []any{map[string]any{"cwe_id": "CWE-89"}},
		"vulnerabilities": []any{map[string]any{"package": map[string]any{"ecosystem": "npm"}}}}
}

func TestBuild_PinsTheParentAndKeysTheFixedSourceLines(t *testing.T) {
	f := fakeFetch(map[string]any{
		"/advisories/GHSA-x": adv("https://github.com/acme/app/commit/abc1234def"),
		"/repos/acme/app/commits/abc1234def": map[string]any{"sha": "abc1234def",
			"parents": []any{map[string]any{"sha": "parent99"}},
			"files": []any{
				map[string]any{"filename": "src/db.ts", "status": "modified", "patch": "@@ -5,3 +5,3 @@\n a\n-bad\n+good\n b\n"},
				map[string]any{"filename": "src/db.test.ts", "status": "modified", "patch": "@@ -1,1 +1,2 @@\n x\n+y\n"},
				map[string]any{"filename": "src/new.ts", "status": "added", "patch": "@@ -0,0 +1,1 @@\n+z\n"},
			}},
	})
	c, err := Build(context.Background(), f, "GHSA-x", BuildOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if c.PreFixCommit != "parent99" || c.Repo != "acme/app" || c.PublishedAt != "2026-09-23" || c.Ecosystem != "npm" {
		t.Fatalf("case metadata wrong: %+v", c)
	}
	if len(c.Golden) != 1 || c.Golden[0] != (Range{"src/db.ts", 6, 6}) {
		t.Fatalf("the key must be the fixed source line only (no tests, no new files): %+v", c.Golden)
	}
}

func TestBuild_SkipsWhatItCannotKeyHonestly(t *testing.T) {
	cases := map[string]map[string]any{
		"no commit":   {"/advisories/GHSA-x": adv("https://example.com/blog")},
		"two commits": {"/advisories/GHSA-x": adv("https://github.com/a/b/commit/1111111", "https://github.com/a/b/commit/2222222")},
		"merge": {"/advisories/GHSA-x": adv("https://github.com/a/b/commit/1111111"),
			"/repos/a/b/commits/1111111": map[string]any{"sha": "1111111", "parents": []any{map[string]any{"sha": "p1"}, map[string]any{"sha": "p2"}}}},
		"docs only": {"/advisories/GHSA-x": adv("https://github.com/a/b/commit/1111111"),
			"/repos/a/b/commits/1111111": map[string]any{"sha": "1111111", "parents": []any{map[string]any{"sha": "p1"}},
				"files": []any{map[string]any{"filename": "README.md", "status": "modified", "patch": "@@ -1 +1 @@\n-a\n+b\n"}}}},
		"truncated patch": {"/advisories/GHSA-x": adv("https://github.com/a/b/commit/1111111"),
			"/repos/a/b/commits/1111111": map[string]any{"sha": "1111111", "parents": []any{map[string]any{"sha": "p1"}},
				"files": []any{map[string]any{"filename": "src/x.go", "status": "modified", "patch": ""}}}},
	}
	for name, m := range cases {
		_, err := Build(context.Background(), fakeFetch(m), "GHSA-x", BuildOptions{})
		var skip ErrSkip
		if !errors.As(err, &skip) {
			t.Errorf("%s: want ErrSkip with a reason, got %v", name, err)
		}
	}
}

// DeepSecBench publishes P, R and score per entry; the formula must reproduce them.
func TestF2MatchesDeepSecBenchsPublishedScore(t *testing.T) {
	if got := 100 * F2(0.9595959595959596, 0.35775862068965516); math.Abs(got-40.907) > 0.01 {
		t.Fatalf("F2 = %.3f, DeepSecBench published 40.907 for that P/R", got)
	}
}

func corpus() []Case {
	return []Case{
		{ID: "A", Repo: "o/a", Golden: []Range{{"src/a.ts", 10, 12}}, PublishedAt: "2026-09-01"},
		{ID: "B", Repo: "o/b", Golden: []Range{{"pkg/b.go", 50, 50}}, PublishedAt: "2026-05-01"},
		{ID: "C", Repo: "o/c", Golden: []Range{{"app/c.py", 5, 5}}, PublishedAt: "2026-09-10"},
	}
}

func TestScoreAll_StrictLenientUnjudgedAndNotRun(t *testing.T) {
	p := Predictions{Tool: "x", Ran: map[string]bool{"A": true, "B": true},
		Errors: map[string]string{"C": "clone failed"},
		Cases: map[string][]Prediction{
			"A": {{File: "/workspace/src/a.ts", Line: 14}, {File: "src/other.ts", Line: 3}}, // strict hit (12+2) + unjudged
			"B": {{File: "pkg/b.go", Line: 200}},                                            // lenient only
		}}
	s := ScoreAll(corpus(), p, DefaultTolerance, "2026-08-01")
	if s.Ran != 2 || s.NotRun != 1 {
		t.Fatalf("ran/not run wrong: %+v", s)
	}
	if s.RecallStrict != 0.5 || s.RecallLenient != 1.0 {
		t.Fatalf("recall strict %.2f lenient %.2f", s.RecallStrict, s.RecallLenient)
	}
	if s.Predictions != 3 || s.Unjudged != 2 || math.Abs(s.PrecisionLB-1.0/3) > 1e-9 {
		t.Fatalf("precision lower bound wrong: %+v", s)
	}
	if s.AfterCutoff != 2 {
		t.Fatalf("after-cutoff count: %d", s.AfterCutoff)
	}
	r := Render(s)
	for _, must := range []string{"LOWER BOUND", "not a head-to-head", "C — clone failed", "unjudged"} {
		if !strings.Contains(r, must) {
			t.Errorf("report missing %q", must)
		}
	}
}

// A case that did not run must not count as a miss — and must not count as a hit either.
func TestScoreAll_NothingRanMeansNoRates(t *testing.T) {
	s := ScoreAll(corpus(), Predictions{Tool: "x"}, DefaultTolerance, "")
	if s.Ran != 0 || s.RecallStrict != 0 || s.F2Strict != 0 || s.NotRun != 3 {
		t.Fatalf("%+v", s)
	}
}

func TestLoad_RefusesBadCases(t *testing.T) {
	dir := t.TempDir()
	write := func(name string, c Case) {
		b, _ := json.Marshal(c)
		_ = os.WriteFile(filepath.Join(dir, name), b, 0o644)
	}
	good := Case{ID: "G", Repo: "o/r", Source: "s", PreFixCommit: "1234567", FixCommit: "7654321", Golden: []Range{{"a.go", 1, 1}}}
	write("g.json", good)
	if _, err := Load(dir); err != nil {
		t.Fatal(err)
	}
	bad := good
	bad.ID, bad.Golden = "B", nil
	write("b.json", bad)
	if _, err := Load(dir); err == nil {
		t.Fatal("a case with no answer key must fail the load, not be skipped")
	}
}
