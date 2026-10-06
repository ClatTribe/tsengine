package codereviewbench

import (
	"context"
	"encoding/json"
	"fmt"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Fetch GETs a GitHub REST path (e.g. "/advisories/GHSA-x") and returns the body. Injected so the
// builder is tested offline and the CLI decides how to authenticate.
type Fetch func(ctx context.Context, apiPath string) ([]byte, error)

// BuildOptions bound which advisories become cases.
type BuildOptions struct {
	// MaxFiles drops an advisory whose fix touches more source files than this (default 5). A fix that
	// rewrites twenty files is a refactor with a security consequence, and its "answer key" would be most
	// of the change — matching it measures nothing.
	MaxFiles int
}

var commitRef = regexp.MustCompile(`^https://github\.com/([^/]+)/([^/]+)/commit/([0-9a-f]{7,40})`)

// ErrSkip is returned (wrapped) when an advisory cannot be made into an honest case. The reason is kept
// so a builder run reports what it declined and why, rather than shrinking the corpus silently.
type ErrSkip struct{ Reason string }

func (e ErrSkip) Error() string { return "skipped: " + e.Reason }

type advisory struct {
	GHSAID      string   `json:"ghsa_id"`
	HTMLURL     string   `json:"html_url"`
	Summary     string   `json:"summary"`
	Severity    string   `json:"severity"`
	PublishedAt string   `json:"published_at"`
	References  []string `json:"references"`
	CWEs        []struct {
		ID string `json:"cwe_id"`
	} `json:"cwes"`
	Vulnerabilities []struct {
		Package struct {
			Ecosystem string `json:"ecosystem"`
		} `json:"package"`
	} `json:"vulnerabilities"`
}

type commit struct {
	SHA     string `json:"sha"`
	Parents []struct {
		SHA string `json:"sha"`
	} `json:"parents"`
	Files []struct {
		Filename string `json:"filename"`
		Status   string `json:"status"`
		Patch    string `json:"patch"`
	} `json:"files"`
}

// Build turns one advisory into a case: exactly one fix commit, pinned at its parent, with the fix's
// changed SOURCE lines as the key.
func Build(ctx context.Context, fetch Fetch, ghsa string, opts BuildOptions) (Case, error) {
	if opts.MaxFiles <= 0 {
		opts.MaxFiles = 5
	}
	raw, err := fetch(ctx, "/advisories/"+ghsa)
	if err != nil {
		return Case{}, err
	}
	var a advisory
	if err := json.Unmarshal(raw, &a); err != nil {
		return Case{}, fmt.Errorf("%s: advisory: %w", ghsa, err)
	}
	var owner, repo, sha string
	n := 0
	seen := map[string]bool{}
	for _, r := range a.References {
		if m := commitRef.FindStringSubmatch(r); m != nil {
			key := m[1] + "/" + m[2] + "@" + m[3]
			if seen[key] {
				continue
			}
			seen[key] = true
			owner, repo, sha = m[1], m[2], m[3]
			n++
		}
	}
	if n != 1 {
		// Zero: nothing to pin. Several: which one is THE fix is a judgement, and a guessed key is worse
		// than no case.
		return Case{}, ErrSkip{fmt.Sprintf("%d fix commits referenced (need exactly one)", n)}
	}
	craw, err := fetch(ctx, fmt.Sprintf("/repos/%s/%s/commits/%s", owner, repo, sha))
	if err != nil {
		return Case{}, err
	}
	var c commit
	if err := json.Unmarshal(craw, &c); err != nil {
		return Case{}, fmt.Errorf("%s: commit: %w", ghsa, err)
	}
	if len(c.Parents) != 1 {
		return Case{}, ErrSkip{fmt.Sprintf("fix commit has %d parents (a merge has no single pre-fix tree)", len(c.Parents))}
	}
	var golden []Range
	files := 0
	for _, f := range c.Files {
		if !isSource(f.Filename) || f.Status == "added" {
			continue // a brand-new file did not exist before the fix, so it cannot be where the bug was
		}
		if f.Patch == "" {
			return Case{}, ErrSkip{"a changed source file has no patch in the API response (too large) — its key would be incomplete"}
		}
		rs := changedOldRanges(f.Filename, f.Patch)
		if len(rs) > 0 {
			files++
			golden = append(golden, rs...)
		}
	}
	if files == 0 {
		return Case{}, ErrSkip{"the fix changes no existing source file"}
	}
	if files > opts.MaxFiles {
		return Case{}, ErrSkip{fmt.Sprintf("the fix touches %d source files (max %d)", files, opts.MaxFiles)}
	}
	out := Case{
		ID: a.GHSAID, Repo: owner + "/" + repo, PreFixCommit: c.Parents[0].SHA, FixCommit: c.SHA,
		Severity: a.Severity, Summary: a.Summary, Source: a.HTMLURL, Golden: golden,
	}
	if len(a.PublishedAt) >= 10 {
		out.PublishedAt = a.PublishedAt[:10]
	}
	if len(a.Vulnerabilities) > 0 {
		out.Ecosystem = strings.ToLower(a.Vulnerabilities[0].Package.Ecosystem)
	}
	for _, w := range a.CWEs {
		out.CWEs = append(out.CWEs, w.ID)
	}
	if out.Source == "" {
		out.Source = "https://github.com/advisories/" + a.GHSAID
	}
	return out, out.Validate()
}

var hunkHeader = regexp.MustCompile(`^@@ -(\d+)(?:,(\d+))? \+\d+(?:,\d+)? @@`)

// changedOldRanges walks a unified-diff patch and returns, in PRE-FIX line numbers, where the fix
// touched the file: every removed line, and for a pure insertion the line it was inserted after. Merged
// into contiguous ranges.
func changedOldRanges(file, patch string) []Range {
	var lines []int
	old := 0
	for _, ln := range strings.Split(patch, "\n") {
		if m := hunkHeader.FindStringSubmatch(ln); m != nil {
			old, _ = strconv.Atoi(m[1])
			continue
		}
		if old == 0 || ln == "" {
			continue
		}
		switch ln[0] {
		case ' ':
			old++
		case '-':
			lines = append(lines, old)
			old++
		case '+':
			// Inserted before old line `old`; anchor on the line above it (or line 1 at the top of a file).
			anchor := old - 1
			if anchor < 1 {
				anchor = 1
			}
			lines = append(lines, anchor)
		case '\\':
			// "\ No newline at end of file"
		}
	}
	if len(lines) == 0 {
		return nil
	}
	sort.Ints(lines)
	var out []Range
	cur := Range{File: file, Start: lines[0], End: lines[0]}
	for _, l := range lines[1:] {
		if l <= cur.End+1 {
			if l > cur.End {
				cur.End = l
			}
			continue
		}
		out = append(out, cur)
		cur = Range{File: file, Start: l, End: l}
	}
	return append(out, cur)
}

var sourceExt = map[string]bool{
	".go": true, ".js": true, ".jsx": true, ".mjs": true, ".cjs": true, ".ts": true, ".tsx": true,
	".py": true, ".rb": true, ".java": true, ".kt": true, ".php": true, ".rs": true, ".cs": true,
	".vue": true, ".svelte": true, ".c": true, ".cc": true, ".cpp": true, ".h": true,
}

// isSource reports whether a changed file can be where a vulnerability lives: source, and not a test.
// Tests, docs, lockfiles and changelogs change in most fixes and are never the bug.
func isSource(p string) bool {
	if !sourceExt[strings.ToLower(path.Ext(p))] {
		return false
	}
	low := strings.ToLower(p)
	base := path.Base(low)
	if strings.Contains(base, "_test.") || strings.Contains(base, ".test.") || strings.Contains(base, ".spec.") ||
		strings.HasPrefix(base, "test_") || strings.HasSuffix(base, "_test.py") {
		return false
	}
	for _, seg := range strings.Split(low, "/") {
		switch seg {
		case "test", "tests", "__tests__", "spec", "testdata", "fixtures", "e2e", "docs", "examples":
			return false
		}
	}
	return true
}
