package llmredteam

import (
	"fmt"
	"strings"
)

// Render formats an engagement report.
func Render(r *Report) string {
	var b strings.Builder
	b.WriteString("=== AI Red-Team operator — engagement ===\n")
	if r.Engagement != "" {
		fmt.Fprintf(&b, "target: %s\n", r.Engagement)
	}
	if r.Summary != "" {
		fmt.Fprintf(&b, "summary: %s\n", r.Summary)
	}
	fmt.Fprintf(&b, "proved %d breach(es) over %d prompt(s), %d tool call(s)\n", len(r.Breaches), r.Turns, r.Calls)
	for _, br := range r.Breaches {
		fmt.Fprintf(&b, "\n[%s] %s  (technique=%s, severity=%s)\n", br.ID, br.Class, br.Technique, br.Severity)
		if br.Rationale != "" {
			fmt.Fprintf(&b, "  why: %s\n", br.Rationale)
		}
		if len(br.Evidence) > 0 {
			fmt.Fprintf(&b, "  evidence turns: %s\n", strings.Join(br.Evidence, ", "))
		}
	}
	return b.String()
}
