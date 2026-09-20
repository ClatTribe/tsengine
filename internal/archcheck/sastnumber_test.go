package archcheck

import (
	"math"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// The SAST Youden figure quoted in PUBLISHED documents must be the one SCOREBOARD.md measured.
//
// # Why this exists
//
// This number has drifted TWICE. `benchmark.md` carried 47.86% after the neutral 2,740-case run
// measured 46.54%, and ADR 0031 logged it as launch-gap D3c; benchmark.md was corrected and the
// competitive collateral was not, so `docs/competitive-proof-sheet.md` went on asserting
// **47.86% Youden ≈ Checkmarx (47)** to the reader most likely to act on it.
//
// The drift was not cosmetic, and that is the whole reason a machine now checks it. Checkmarx
// scores 47. At the invented 47.86 we are ABOVE it and the sentence "≈ Checkmarx" reads as parity;
// at the measured 46.54 we are BELOW it. A stale number did not merely age — it INVERTED the
// direction of a competitive claim in the document written to be quoted at buyers. That is §0's
// "claims ahead of measurement" and §10's grounding rule pointed at our own marketing.
//
// # What it checks, and what it deliberately does not
//
// SCOREBOARD.md is the regenerated artifact ("every figure below was produced on this machine, not
// carried forward"), so it is the source of truth and this test reads the number FROM it rather
// than hard-coding one — a guard carrying its own copy of the answer is the next thing to go stale.
//
// It accepts the figure at full precision (46.54%) or correctly rounded to one decimal (46.5%),
// because both are honest renderings and docs legitimately use both. Anything else fails.
//
// It does NOT parse the surrounding prose. "≈ Checkmarx" is a judgement about what the number
// MEANS, and a test that graded English would be the brittle parser this package's header refuses
// to write. It pins the mechanical half — the digits — and leaves the comparison to review.
func TestPublishedSASTNumberMatchesTheScoreboard(t *testing.T) {
	root := repoRoot(t)
	want := authoritativeSAST(t, root)

	// Accept full precision or a correct 1-decimal rounding of it.
	wantRounded := math.Round(want*10) / 10

	docs := publishedMarkdown(t, root)
	if len(docs) == 0 {
		t.Fatal("no published markdown found — a guard that cannot see its subject must fail, not pass")
	}

	checked := 0
	for _, path := range docs {
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("cannot read %s (%v) — a document that cannot be read goes unverified while this test reports green", path, err)
		}
		rel, _ := filepath.Rel(root, path)
		text := string(b)
		for _, loc := range youdenClaimRe.FindAllStringSubmatchIndex(text, -1) {
			// Youden is reported for MORE than SAST — WAVSEP publishes a per-class DAST figure
			// (SQLi 57.58%) that is a different measurement of a different asset. Matching every
			// decimal-Youden claim flagged that one on the first run, which would have made this
			// guard demand a doc restate a DAST number as a SAST one. So the claim only counts
			// when its immediate context names the SAST benchmark.
			if !sastContext(text, loc[0], loc[1]) {
				continue
			}
			raw := group(text, loc, 1) + group(text, loc, 2) // exactly one group is non-empty
			got, err := strconv.ParseFloat(strings.TrimSpace(raw), 64)
			if err != nil {
				continue
			}
			checked++
			if !closeEnough(got, want) && !closeEnough(got, wantRounded) {
				t.Errorf("%s asserts %.2f%% Youden; SCOREBOARD.md measured %.2f%%. "+
					"A superseded benchmark number in a published document is a claim ahead of "+
					"measurement — and this one has previously inverted our standing against "+
					"Checkmarx (47). Update the doc, or re-run the bench and regenerate SCOREBOARD.md.",
					rel, got, want)
			}
		}
	}

	// A pattern that matches nothing passes vacuously (§14.2 rule 6). The docs carried 11 such
	// claims when this landed; the floor sits below that so ordinary editing does not trip it, but
	// a reword that silently stops quoting the number at all still fails loudly.
	const floor = 6
	if checked < floor {
		t.Errorf("only %d SAST Youden claim(s) found across published docs (floor %d) — the pattern "+
			"has stopped matching, so this guard is no longer checking what it claims to", checked, floor)
	}
}

// youdenClaimRe matches OUR claimed figure in either order, with or without a space before %.
// It requires a DECIMAL, which is what distinguishes our measured score from the competitor bars
// the same tables list as whole numbers (Veracode 51, Checkmarx 47, Fortify 35).
var youdenClaimRe = regexp.MustCompile(`(?:([0-9]+\.[0-9]+)\s?%\s?Youden|Youden\s+([0-9]+\.[0-9]+)\s?%)`)

// scoreboardSASTRe pulls the bolded percentage out of SCOREBOARD.md's Repository · SAST row.
var scoreboardSASTRe = regexp.MustCompile(`Repository · SAST[^|]*\|[^|]*\|\s*\*\*([0-9]+\.[0-9]+)%\*\*`)

func authoritativeSAST(t *testing.T, root string) float64 {
	t.Helper()
	path := filepath.Join(root, "SCOREBOARD.md")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("cannot read SCOREBOARD.md (%v) — it is the source of truth for this number, so "+
			"without it every doc claim goes unverified", err)
	}
	m := scoreboardSASTRe.FindStringSubmatch(string(b))
	if len(m) < 2 {
		t.Fatal("SCOREBOARD.md no longer states a Repository · SAST percentage in the expected shape — " +
			"the guard cannot read its own answer key, which must fail rather than silently pass")
	}
	v, err := strconv.ParseFloat(m[1], 64)
	if err != nil {
		t.Fatalf("SCOREBOARD.md SAST figure %q is not a number: %v", m[1], err)
	}
	return v
}

// publishedMarkdown is every .md a reader (or an agent) consults: repo root + docs/, recursively.
// Walking rather than listing means a NEW document quoting the number is covered the day it lands,
// which is precisely how the figure drifted the first time.
func publishedMarkdown(t *testing.T, root string) []string {
	t.Helper()
	var out []string
	add := func(dir string, recurse bool) {
		err := filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if info.IsDir() {
				if !recurse && p != dir {
					return filepath.SkipDir
				}
				if strings.Contains(p, "node_modules") {
					return filepath.SkipDir
				}
				return nil
			}
			if strings.HasSuffix(p, ".md") {
				out = append(out, p)
			}
			return nil
		})
		if err != nil {
			t.Fatalf("cannot walk %s: %v", dir, err)
		}
	}
	add(root, false)
	add(filepath.Join(root, "docs"), true)
	return out
}

// sastContext reports whether a Youden claim at [start,end) is about the SAST benchmark, judged by
// the text immediately around it. The window is deliberately tight: widened far enough, every
// number in a scoreboard table sits near the word "SAST" and the scoping stops discriminating.
func sastContext(text string, start, end int) bool {
	const window = 160
	lo := start - window
	if lo < 0 {
		lo = 0
	}
	hi := end + window
	if hi > len(text) {
		hi = len(text)
	}
	ctx := strings.ToLower(text[lo:hi])
	return strings.Contains(ctx, "sast") ||
		strings.Contains(ctx, "owasp benchmark") ||
		strings.Contains(ctx, "benchmarkjava")
}

// group returns submatch n from a FindAllStringSubmatchIndex location, or "" when it did not match.
func group(text string, loc []int, n int) string {
	a, b := loc[2*n], loc[2*n+1]
	if a < 0 || b < 0 {
		return ""
	}
	return text[a:b]
}

func closeEnough(a, b float64) bool { return math.Abs(a-b) < 0.001 }
