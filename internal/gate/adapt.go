package gate

import (
	"fmt"
	"strings"

	"github.com/ClatTribe/tsengine/internal/reachability"
	"github.com/ClatTribe/tsengine/internal/report"
)

// FromReport adapts a normalized report (built from an L1 scan, a web evidence
// bundle, or an LLM red-team report) into gate findings.
func FromReport(r *report.Report) []Finding {
	src := "scan"
	switch {
	case strings.Contains(r.Kind, "Web"):
		src = "web"
	case strings.Contains(r.Kind, "LLM"), strings.Contains(r.Kind, "Red-Team"):
		src = "llm"
	}
	out := make([]Finding, 0, len(r.Findings))
	for _, f := range r.Findings {
		out = append(out, Finding{
			ID: f.ID, Title: f.Title, Severity: f.Severity, Source: src,
			Verified: f.Status == "verified",
		})
	}
	return out
}

// FromReachability adapts SCA reachability triage into gate findings (source "sca",
// Reachable set from the triage priority).
func FromReachability(results []reachability.TriageResult) []Finding {
	out := make([]Finding, 0, len(results))
	for _, t := range results {
		title := t.Finding.Package
		if t.Finding.CVE != "" {
			title = t.Finding.CVE + " in " + t.Finding.Package
		}
		out = append(out, Finding{
			ID: t.Finding.ID, Title: title, Severity: t.Finding.Severity, Source: "sca",
			Reachable: t.Priority == "reachable",
		})
	}
	return out
}

// Render formats a human-readable gate result.
func Render(r Result) string {
	var b strings.Builder
	verdict := "PASS ✓"
	if !r.Passed {
		verdict = "FAIL ✗"
	}
	fmt.Fprintf(&b, "=== tsengine CI gate: %s ===\n", verdict)
	fmt.Fprintf(&b, "%d finding(s): %d gated, %d existing (baseline), %d waived; %d new\n",
		r.Total, r.Gated, r.Existing, r.Waived, r.New)
	if len(r.Counts) > 0 {
		fmt.Fprintf(&b, "severity: %s\n", sevLine(r.Counts))
	}
	if len(r.Violations) == 0 {
		b.WriteString("no policy violations.\n")
		return b.String()
	}
	fmt.Fprintf(&b, "\n%d violation(s):\n", len(r.Violations))
	for _, v := range r.Violations {
		if v.Title == "" {
			fmt.Fprintf(&b, "  ✗ %s\n", v.Reason)
			continue
		}
		fmt.Fprintf(&b, "  ✗ [%s] %s (%s) — %s\n", strings.ToUpper(v.Severity), v.Title, v.Source, v.Reason)
	}
	return b.String()
}

// RenderGitHub emits GitHub-Actions annotations (one ::error:: per violation) so
// failures surface inline on the PR.
func RenderGitHub(r Result) string {
	var b strings.Builder
	for _, v := range r.Violations {
		title := v.Title
		if title == "" {
			title = "policy"
		}
		fmt.Fprintf(&b, "::error title=tsengine gate: %s::%s\n", escapeAnno(title), escapeAnno(v.Reason))
	}
	status := "passed"
	if !r.Passed {
		status = "FAILED"
	}
	fmt.Fprintf(&b, "::notice::tsengine gate %s — %d violation(s), %d new finding(s)\n", status, len(r.Violations), r.New)
	return b.String()
}

func escapeAnno(s string) string {
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "%", "%25")
	return s
}

func sevLine(c map[string]int) string {
	var parts []string
	for _, sev := range []string{"critical", "high", "medium", "low", "info"} {
		if c[sev] > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", c[sev], sev))
		}
	}
	return strings.Join(parts, ", ")
}
