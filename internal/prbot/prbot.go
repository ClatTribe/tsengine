// Package prbot is the repository PR-inline review bot (ADR 0010 Phase 2) — the developer-loop
// capability that makes Aikido/Snyk sticky for SMB devs: instead of a separate dashboard, the
// engine's findings land as inline comments on the exact changed lines of a pull request, plus a
// pass/fail check that can gate the merge. This is the deterministic core — the diff→comments
// mapper + the check conclusion — wrapped by a (gated) GitHub post.
//
// Scoping discipline (what makes a PR bot usable, not noisy): comment ONLY on findings that land
// on a line the PR actually changed. A repo can have 500 pre-existing findings; the PR author
// cares about the ones their diff introduced/touched. Everything else stays on the dashboard.
package prbot

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/ClatTribe/tsengine/pkg/types"
)

// ChangedFile is one file in a PR diff and the set of (new-side) line numbers it added/changed —
// the lines a review comment can attach to (GitHub only accepts comments on diff lines).
type ChangedFile struct {
	Path  string
	Lines map[int]bool
}

// Comment is one inline review comment to post.
type Comment struct {
	Path     string         `json:"path"`
	Line     int            `json:"line"`
	Severity types.Severity `json:"severity"`
	RuleID   string         `json:"rule_id"`
	Body     string         `json:"body"`
}

// Review is the full PR verdict: the inline comments + a check-run conclusion + a summary.
type Review struct {
	Comments   []Comment `json:"comments"`
	Conclusion string    `json:"conclusion"` // success | failure | neutral (GitHub check-run)
	Summary    string    `json:"summary"`
}

// endpointRe pulls "path:line" out of a finding endpoint ("src/app.go:42", "a.go:42:7", …).
var endpointRe = regexp.MustCompile(`^(.*?):(\d+)`)

// FileLine parses a repo finding's endpoint into (path, line). ok=false when it isn't a
// file:line (e.g. a URL endpoint from a non-repo finding) — those never become PR comments.
func FileLine(endpoint string) (path string, line int, ok bool) {
	m := endpointRe.FindStringSubmatch(strings.TrimSpace(endpoint))
	if m == nil {
		return "", 0, false
	}
	n, err := strconv.Atoi(m[2])
	if err != nil {
		return "", 0, false
	}
	return m[1], n, true
}

// Build maps findings onto a PR's changed lines and produces the review. blockAt is the
// severity floor that fails the check (e.g. SeverityHigh: a high+ finding on a changed line
// blocks the merge). Only findings whose file:line is in the diff become comments — so the bot
// reviews what the PR touched, never the whole backlog.
func Build(findings []types.Finding, changed []ChangedFile, blockAt types.Severity) Review {
	idx := map[string]map[int]bool{}
	for _, cf := range changed {
		idx[normPath(cf.Path)] = cf.Lines
	}

	var comments []Comment
	worst := 0
	for _, f := range findings {
		path, line, ok := FileLine(f.Endpoint)
		if !ok {
			continue
		}
		lines := idx[normPath(path)]
		if lines == nil || !lines[line] {
			continue // the finding isn't on a line this PR changed — leave it on the dashboard
		}
		comments = append(comments, Comment{
			Path: path, Line: line, Severity: f.Severity, RuleID: f.RuleID, Body: commentBody(f),
		})
		if r := f.Severity.Rank(); r > worst {
			worst = r
		}
	}
	sort.SliceStable(comments, func(i, j int) bool {
		if comments[i].Path != comments[j].Path {
			return comments[i].Path < comments[j].Path
		}
		return comments[i].Line < comments[j].Line
	})

	return Review{
		Comments:   comments,
		Conclusion: conclusion(comments, worst, blockAt),
		Summary:    summary(comments, blockAt),
	}
}

func conclusion(comments []Comment, worst int, blockAt types.Severity) string {
	if len(comments) == 0 {
		return "success" // nothing new in the diff → green
	}
	if worst >= blockAt.Rank() {
		return "failure" // a blocking-severity issue on a changed line → fail the check
	}
	return "neutral" // findings present but below the block floor → informational, non-blocking
}

func summary(comments []Comment, blockAt types.Severity) string {
	if len(comments) == 0 {
		return "tsengine: no new security findings on the changed lines. ✅"
	}
	blocking := 0
	for _, c := range comments {
		if c.Severity.Rank() >= blockAt.Rank() {
			blocking++
		}
	}
	return fmt.Sprintf("tsengine: %d finding(s) on changed lines, %d at or above %s (the merge-block floor).",
		len(comments), blocking, blockAt)
}

func commentBody(f types.Finding) string {
	var b strings.Builder
	fmt.Fprintf(&b, "**%s** · `%s` · %s\n\n", titleCase(string(f.Severity)), f.RuleID, firstNonEmpty(f.Title, f.RuleID))
	if d := strings.TrimSpace(f.Description); d != "" {
		b.WriteString(d)
		b.WriteString("\n\n")
	}
	if len(f.CWE) > 0 {
		fmt.Fprintf(&b, "_%s_ · ", strings.Join(f.CWE, ", "))
	}
	b.WriteString("flagged by tsengine on this changed line.")
	return b.String()
}

func normPath(p string) string { return strings.TrimPrefix(strings.TrimSpace(p), "./") }

func titleCase(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

func firstNonEmpty(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return a
	}
	return b
}
