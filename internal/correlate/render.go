package correlate

import (
	"fmt"
	"strings"
)

// Render formats correlated cross-asset attack chains.
func Render(chains []Chain) string {
	var b strings.Builder
	if len(chains) == 0 {
		return "=== cross-asset correlation ===\nno cross-asset attack chains found (no finding bridges to a crown jewel).\n"
	}
	fmt.Fprintf(&b, "=== cross-asset correlation ===\n%d attack chain(s) — external entry → crown jewel:\n", len(chains))
	for i, c := range chains {
		fmt.Fprintf(&b, "\nCHAIN %d  (%s)\n", i+1, strings.ToUpper(c.Severity))
		for j, s := range c.Steps {
			tag := ""
			if s.Verified {
				tag = " ✓verified"
			}
			if s.CrownJewel {
				tag += "  ← CROWN JEWEL"
			}
			fmt.Fprintf(&b, "  %d. [%s %s] %s%s\n", j+1, s.AssetType, s.AssetTarget, s.Title, tag)
			if s.ViaEntity != "" {
				fmt.Fprintf(&b, "       ↓ bridged by %s\n", s.ViaEntity)
			}
		}
	}
	return b.String()
}
