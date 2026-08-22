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
	// A missing score is reported as MISSING, never as 0.0.
	//
	// 0.0 is a real CVSS score and it means no impact — the strongest de-prioritisation signal there is.
	// Only NVD populates this field (threatintel.go: "this is the source that populates CVSS") and NVD is
	// opt-in, so on a refreshed corpus every entry carries 0 and this line was telling the agent that
	// Log4Shell scores zero. The two human-facing surfaces already guard it (the finding page renders the
	// score only when > 0, the VAPT report likewise); the agent's channel did not — the exact inverse of
	// the weapon_rank gap, where the agent was told something the human was not.
	if ti.CVSS > 0 {
		fmt.Fprintf(&b, "%s — CVSS %.1f", cve, ti.CVSS)
	} else {
		fmt.Fprintf(&b, "%s — CVSS unavailable (NVD not ingested; absent, not zero)", cve)
	}
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
