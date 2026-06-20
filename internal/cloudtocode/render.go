package cloudtocode

import (
	"fmt"
	"sort"
	"strings"

	"github.com/ClatTribe/tsengine/pkg/types"
)

// Linked returns the subset of findings that carry a Cloud-to-Code provenance,
// sorted by file:line for a stable report.
func Linked(findings []types.Finding) []types.Finding {
	var out []types.Finding
	for _, f := range findings {
		if f.CodeProvenance != nil {
			out = append(out, f)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i].CodeProvenance, out[j].CodeProvenance
		if a.File != b.File {
			return a.File < b.File
		}
		return a.Line < b.Line
	})
	return out
}

// Render produces a human-readable Cloud-to-Code report: each linked cloud
// finding and the IaC file:line that provisioned it. total is the number of
// cloud findings considered, so the reader sees the link rate.
func Render(findings []types.Finding, total int) string {
	linked := Linked(findings)
	var b strings.Builder
	fmt.Fprintf(&b, "Cloud-to-Code: %d of %d cloud finding(s) linked to IaC source\n", len(linked), total)
	if len(linked) == 0 {
		b.WriteString("\n  No findings could be confidently traced to source. (No matching\n")
		b.WriteString("  resource in the IaC tree, or the physical name is computed at apply\n")
		b.WriteString("  time — no link is reported rather than a guessed one.)\n")
		return b.String()
	}
	b.WriteString("\n")
	for _, f := range linked {
		p := f.CodeProvenance
		fmt.Fprintf(&b, "  [%s] %s\n", strings.ToUpper(string(f.Severity)), f.Title)
		fmt.Fprintf(&b, "      rule:   %s\n", f.RuleID)
		fmt.Fprintf(&b, "      source: %s:%d  (%s)\n", p.File, p.Line, p.IaCResource)
		fmt.Fprintf(&b, "      why:    %s — matched on %q  [%s confidence]\n", p.MatchBasis, p.MatchedOn, p.Confidence)
	}
	return b.String()
}
