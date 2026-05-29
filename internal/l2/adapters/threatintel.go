package adapters

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/ClatTribe/tsengine/internal/l2"
	"github.com/ClatTribe/tsengine/internal/tracer/hooks"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// ThreatIntel adapts the L1.5 threat-intel corpus (hooks.ThreatIntel) to the
// L2 query_threat_intel tool. ONE corpus, pinned per scan (§10) — not strix's
// live NVD REST + Perplexity Sonar calls (which are nondeterministic and need
// runtime API keys). Renders the structured annotation to the compact text
// the model reads.
type ThreatIntel struct{ h *hooks.ThreatIntel }

var _ l2.ThreatIntelLookup = (*ThreatIntel)(nil)

// NewThreatIntel loads the embedded/pinned corpus via the L1.5 hook.
func NewThreatIntel() *ThreatIntel { return &ThreatIntel{h: hooks.NewThreatIntel()} }

// LookupCVE implements l2.ThreatIntelLookup.
func (a *ThreatIntel) LookupCVE(_ context.Context, cve string) (string, bool) {
	ti, ok := a.h.Lookup(strings.ToUpper(strings.TrimSpace(cve)))
	if !ok {
		return "", false
	}
	return renderThreatIntel(strings.ToUpper(strings.TrimSpace(cve)), ti), true
}

// renderThreatIntel renders CVSS / KEV / EPSS / exploits / advisories as a
// one-line prioritization summary. KEV + EPSS lead because they drive patch
// priority (a KEV-listed, high-EPSS CVE outranks a higher-CVSS dormant one).
func renderThreatIntel(cve string, ti *types.ThreatIntel) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s — CVSS %.1f", cve, ti.CVSS)
	if ti.KEV != nil && ti.KEV.Listed {
		b.WriteString("; KEV: LISTED")
		if !ti.KEV.DateAdded.IsZero() {
			fmt.Fprintf(&b, " (added %s)", ti.KEV.DateAdded.Format(time.DateOnly))
		}
	} else {
		b.WriteString("; KEV: not listed")
	}
	if ti.EPSS != nil {
		fmt.Fprintf(&b, "; EPSS %.4f (p%.0f)", ti.EPSS.Score, ti.EPSS.Percentile*100)
	}
	if len(ti.Exploits) > 0 {
		fmt.Fprintf(&b, "; known exploits: %s", strings.Join(ti.Exploits, ", "))
	}
	if len(ti.Advisories) > 0 {
		fmt.Fprintf(&b, "; advisories: %s", strings.Join(ti.Advisories, ", "))
	}
	return b.String()
}
