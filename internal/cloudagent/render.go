package cloudagent

import (
	"fmt"
	"strings"
)

// Render formats the agent's report.
func Render(r *Report) string {
	var b strings.Builder
	b.WriteString("=== AI Cloud Security Engineer (LLM agent) — investigation ===\n")
	if r.Summary != "" {
		fmt.Fprintf(&b, "summary: %s\n", r.Summary)
	}
	fmt.Fprintf(&b, "determined %d real attack path(s) over %d tool call(s)\n", len(r.Issues), r.Calls)
	for _, is := range r.Issues {
		fmt.Fprintf(&b, "\n[%s] %s  (severity=%s)\n", is.ID, is.TargetName, is.Severity)
		fmt.Fprintf(&b, "  path: %s\n", strings.Join(is.Path, " -> "))
		if is.Rationale != "" {
			fmt.Fprintf(&b, "  why: %s\n", is.Rationale)
		}
		if len(is.Evidence) > 0 {
			fmt.Fprintf(&b, "  evidence: %s\n", strings.Join(is.Evidence, "; "))
		}
		if is.Remediation != "" {
			tick := " "
			if is.FixVerified {
				tick = "✓"
			}
			fmt.Fprintf(&b, "  fix[%s]: %s (%s)\n", tick, is.Remediation, is.FixKind)
		}
	}
	return b.String()
}
