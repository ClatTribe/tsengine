package hooks

import (
	_ "embed"
	"encoding/json"
	"regexp"
	"time"

	"github.com/ClatTribe/tsengine/pkg/types"
)

//go:embed data/threat_intel.json
var threatIntelCorpus []byte

// ThreatIntel implements hook 6 of CLAUDE.md §11 + §7. For any finding
// carrying a CVE (extracted from its rule_id), it looks up CVSS / KEV /
// EPSS / advisories from the embedded corpus and attaches a ThreatIntel
// annotation.
//
// This is L1 work, not L2: compliance teams need KEV listing immediately
// (SLA clocks) and security teams need EPSS for patch priority — both
// read the dashboard, not the LLM's translation. The embedded corpus is
// a Phase-4 static snapshot; Phase 5 wires the cron-refreshed,
// per-scan-pinned corpus.
type ThreatIntel struct {
	corpus map[string]corpusEntry
}

type corpusEntry struct {
	CVSS       float64          `json:"cvss"`
	KEV        *types.KEVStatus `json:"kev"`
	EPSS       *types.EPSSScore `json:"epss"`
	Advisories []string         `json:"advisories"`
	Exploits   []string         `json:"exploits"`
}

// cvePattern extracts a CVE id from a rule_id like "trivy::CVE-2021-42374".
var cvePattern = regexp.MustCompile(`CVE-\d{4}-\d{3,7}`)

// NewThreatIntel loads the embedded corpus. Panics on a malformed
// corpus — that's a build-time error, not a runtime one.
func NewThreatIntel() *ThreatIntel {
	var c map[string]corpusEntry
	if err := json.Unmarshal(threatIntelCorpus, &c); err != nil {
		panic("hooks: malformed embedded threat_intel corpus: " + err.Error())
	}
	return &ThreatIntel{corpus: c}
}

func (*ThreatIntel) Name() string { return "threat_intel" }

// Lookup returns the threat-intel annotation for a CVE id from the pinned
// corpus, or (nil,false) if absent. It is the single corpus access path,
// shared by the L1.5 Apply hook AND the L2 query_threat_intel adapter
// (internal/l2/adapters) — so L2's "real-time data" tool and L1's enrichment
// read the same versioned snapshot, never diverging (and never a live API
// call that would break reproducibility, §10).
func (h *ThreatIntel) Lookup(cve string) (*types.ThreatIntel, bool) {
	entry, ok := h.corpus[cve]
	if !ok {
		return nil, false
	}
	return &types.ThreatIntel{
		CVSS:       entry.CVSS,
		KEV:        entry.KEV,
		EPSS:       entry.EPSS,
		Advisories: entry.Advisories,
		Exploits:   entry.Exploits,
	}, true
}

// Apply enriches CVE-bearing findings. Annotation-only — never drops or
// changes severity (KEV-driven severity escalation is a deliberate
// future enrichment, gated behind policy).
func (h *ThreatIntel) Apply(f types.Finding) (types.Finding, []types.AuditEntry, bool) {
	cve := cvePattern.FindString(f.RuleID)
	if cve == "" {
		return f, nil, true
	}
	ti, ok := h.Lookup(cve)
	if !ok {
		return f, nil, true
	}
	f.ThreatIntel = ti

	// A KEV listing is materially important — log it to the audit trail
	// so the compliance audience sees the SLA-clock trigger explicitly.
	if ti.KEV != nil && ti.KEV.Listed {
		return f, []types.AuditEntry{{
			FindingID: f.ID,
			Action:    "annotate",
			Rule:      "threat_intel::kev-listed",
			Reason:    cve + " is on the CISA KEV catalog (added " + kevDate(ti.KEV) + ")",
		}}, true
	}
	return f, nil, true
}

func kevDate(k *types.KEVStatus) string {
	if k == nil || k.DateAdded.IsZero() {
		return "unknown"
	}
	return k.DateAdded.Format(time.DateOnly)
}
