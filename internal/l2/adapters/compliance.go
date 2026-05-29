package adapters

import (
	"strings"

	"github.com/ClatTribe/tsengine/internal/l2"
	"github.com/ClatTribe/tsengine/internal/tracer/hooks"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// Compliance adapts the L1.5 compliance corpus (hooks.Compliance) to the L2
// lookup_compliance_mapping tool — CWE(s) → the SOC2/PCI/HIPAA/CIS/NIST/ISO
// controls they affect, so the Lead can phrase remediation in the customer's
// audit language. Same pinned corpus the L1.5 hook annotates findings with.
type Compliance struct{ h *hooks.Compliance }

var _ l2.ComplianceLookup = (*Compliance)(nil)

// NewCompliance loads the embedded/pinned corpus via the L1.5 hook.
func NewCompliance() *Compliance { return &Compliance{h: hooks.NewCompliance()} }

// MapCWE implements l2.ComplianceLookup. Returns "" when no control maps (the
// tool reports "no controls" in that case).
func (a *Compliance) MapCWE(cwes []string) string {
	c, ok := a.h.Lookup(cwes)
	if !ok {
		return ""
	}
	return renderCompliance(cwes, c)
}

func renderCompliance(cwes []string, c *types.Compliance) string {
	var parts []string
	add := func(label string, vals []string) {
		if len(vals) > 0 {
			parts = append(parts, label+" "+strings.Join(vals, ","))
		}
	}
	add("SOC2", c.SOC2)
	add("PCI", c.PCI)
	add("HIPAA", c.HIPAA)
	add("CIS-v8", c.CISv8)
	add("NIST-CSF", c.NISTCSF)
	add("ISO-27001", c.ISO27001)
	if len(parts) == 0 {
		return ""
	}
	return strings.Join(cwes, ",") + " → " + strings.Join(parts, "; ")
}
