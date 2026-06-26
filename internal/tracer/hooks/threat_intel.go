package hooks

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"time"

	"github.com/ClatTribe/tsengine/internal/corpus/threatintel"
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
	corpus   map[string]corpusEntry
	version  string    // pinned corpus version (embedded const or manifest)
	snapshot time.Time // as-of of the intel data (embedded snapshot or EPSS as-of)
}

type corpusEntry struct {
	CVSS       float64          `json:"cvss"`
	CVSSVector string           `json:"cvss_vector"`
	KEV        *types.KEVStatus `json:"kev"`
	EPSS       *types.EPSSScore `json:"epss"`
	Advisories []string         `json:"advisories"`
	Exploits   []string         `json:"exploits"`
}

// cvePattern extracts a CVE id from a rule_id like "trivy::CVE-2021-42374".
var cvePattern = regexp.MustCompile(`CVE-\d{4}-\d{3,7}`)

// ThreatIntelCorpusEnv points at a refreshed on-disk OSINT corpus (the
// KEV+EPSS data file written by `tsengine corpus refresh`). When set and
// loadable it overrides the embedded snapshot.
const ThreatIntelCorpusEnv = "TSENGINE_THREAT_INTEL_CORPUS"

// NewThreatIntel loads the threat-intel corpus: the refreshed on-disk OSINT
// corpus when TSENGINE_THREAT_INTEL_CORPUS points at one, else the embedded
// snapshot. The embedded corpus is the static Phase-4 fallback; the on-disk
// corpus is the cron-refreshed CISA-KEV + FIRST.org-EPSS snapshot, pinned per
// scan (CLAUDE.md §5/§7/§10). A bad on-disk path logs + falls back, never
// crashes the scan.
func NewThreatIntel() *ThreatIntel {
	if path := os.Getenv(ThreatIntelCorpusEnv); path != "" {
		if h, err := loadThreatIntelFile(path); err == nil {
			return h
		} else {
			fmt.Fprintf(os.Stderr, "[threat_intel] on-disk corpus %q unusable (%v); using embedded snapshot\n", path, err)
		}
	}
	return loadThreatIntelEmbedded()
}

// loadThreatIntelEmbedded parses the embedded snapshot. Panics on malformed
// data — a build-time error, not a runtime one.
func loadThreatIntelEmbedded() *ThreatIntel {
	var c map[string]corpusEntry
	if err := json.Unmarshal(threatIntelCorpus, &c); err != nil {
		panic("hooks: malformed embedded threat_intel corpus: " + err.Error())
	}
	return &ThreatIntel{corpus: c, version: ThreatIntelCorpusVersion, snapshot: ThreatIntelSnapshot}
}

// loadThreatIntelFile loads a refreshed on-disk OSINT corpus (a bare
// map[CVE]Entry, byte-compatible with the embedded snapshot) plus its sidecar
// manifest for version + as-of provenance.
func loadThreatIntelFile(path string) (*ThreatIntel, error) {
	b, err := os.ReadFile(path) //nolint:gosec // operator-provided corpus path
	if err != nil {
		return nil, err
	}
	var c map[string]corpusEntry
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("parse on-disk threat_intel corpus: %w", err)
	}
	if len(c) == 0 {
		return nil, fmt.Errorf("on-disk threat_intel corpus is empty")
	}
	h := &ThreatIntel{corpus: c, version: "threat-intel-ondisk"}
	if m, mErr := threatintel.LoadManifest(path); mErr == nil {
		h.version = m.Version
		h.snapshot = m.EPSSAsOf
	}
	return h, nil
}

// CorpusVersion is the pinned corpus version (embedded const or on-disk
// manifest), recorded into the scan's corpus block.
func (h *ThreatIntel) CorpusVersion() string { return h.version }

// Snapshot is the as-of of the intel data.
func (h *ThreatIntel) Snapshot() time.Time { return h.snapshot }

// ThreatIntelCorpusInfo reports the pinned corpus version + KEV/EPSS as-of
// dates for the scan's corpus block — reading the cheap manifest when an
// on-disk OSINT corpus is configured, else the embedded constants. It does
// NOT load the full corpus.
func ThreatIntelCorpusInfo() (version string, kevAsOf, epssAsOf time.Time) {
	if path := os.Getenv(ThreatIntelCorpusEnv); path != "" {
		if m, err := threatintel.LoadManifest(path); err == nil {
			return m.Version, m.KEVAsOf, m.EPSSAsOf
		}
	}
	return ThreatIntelCorpusVersion, ThreatIntelSnapshot, ThreatIntelSnapshot
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
		CVSSVector: entry.CVSSVector,
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
