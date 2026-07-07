package codeagent

import (
	"fmt"
	"strings"
)

// Render turns a Report into a compact plain-text digest for the L2 generalist that delegated to this
// specialist (mirrors cloudagent.Render). It leads with the exploitable, source-grounded issues — the
// depth the generalist couldn't reach from a finding summary.
func Render(rep *Report) string {
	if rep == nil {
		return "code specialist returned nothing."
	}
	var b strings.Builder
	if rep.Summary != "" {
		b.WriteString(rep.Summary)
		b.WriteString("\n\n")
	}
	var exploit, contained int
	for _, is := range rep.Issues {
		if is.Exploitable {
			exploit++
		} else {
			contained++
		}
	}
	fmt.Fprintf(&b, "code specialist: %d finding(s) assessed at source — %d confirmed EXPLOITABLE, %d contained (noise) — in %d tool calls.\n",
		len(rep.Issues), exploit, contained, rep.Calls)
	for _, is := range rep.Issues {
		verdict := "contained"
		if is.Exploitable {
			verdict = "EXPLOITABLE"
		}
		fmt.Fprintf(&b, "\n- [%s] %s (%s)\n", verdict, firstNonEmpty(is.Title, is.FindingID), is.Severity)
		if is.Rationale != "" {
			fmt.Fprintf(&b, "  why: %s\n", is.Rationale)
		}
		if is.BlastRadius != "" {
			fmt.Fprintf(&b, "  blast radius: %s\n", is.BlastRadius)
		}
		if is.FixLocation != "" || is.Fix != "" {
			fmt.Fprintf(&b, "  fix (%s): %s\n", firstNonEmpty(is.FixLocation, "see below"), is.Fix)
		}
		if len(is.Evidence) > 0 {
			fmt.Fprintf(&b, "  grounded in: %s\n", strings.Join(is.Evidence, ", "))
		}
	}
	return strings.TrimRight(b.String(), "\n")
}
