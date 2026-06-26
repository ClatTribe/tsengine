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
	corpus      map[string]corpusEntry
	version     string    // pinned corpus version (embedded const or manifest)
	snapshot    time.Time // as-of of the intel data (embedded snapshot or EPSS as-of)
	escalateKEV bool      // opt-in (TSENGINE_KEV_ESCALATE): bump a sub-high finding to high when its CVE is on CISA KEV
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

// KEVEscalateEnv opts IN to KEV-driven severity escalation (the deliberate-future enrichment this hook's
// Apply documents). When "1"/"true", a finding whose CVE is on the CISA KEV catalog but rated below high is
// bumped to high — KEV means actively exploited in the wild (the strongest "patch now" signal, and the
// trigger for CISA BOD 22-01 SLA clocks). Default OFF preserves the annotation-only contract; grounded (§10):
// it acts ONLY on a real KEV listing in the corpus, and never downgrades.
const KEVEscalateEnv = "TSENGINE_KEV_ESCALATE"

func kevEscalateEnabled() bool {
	switch os.Getenv(KEVEscalateEnv) {
	case "1", "true", "TRUE", "yes":
		return true
	}
	return false
}

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
	return &ThreatIntel{corpus: c, version: ThreatIntelCorpusVersion, snapshot: ThreatIntelSnapshot, escalateKEV: kevEscalateEnabled()}
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
	h := &ThreatIntel{corpus: c, version: "threat-intel-ondisk", escalateKEV: kevEscalateEnabled()}
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

// Apply enriches CVE-bearing findings. Annotation-only by default; KEV-driven severity escalation is the
// deliberate, policy-gated enrichment (TSENGINE_KEV_ESCALATE — KEVEscalateEnv). Grounded (§10): it acts only
// on a real KEV listing in the pinned corpus, only bumps UP (never downgrades), and logs the promotion.
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

	if ti.KEV != nil && ti.KEV.Listed {
		// Opt-in escalation: a CVE actively exploited in the wild but rated below high is materially
		// under-prioritized — bump it to high (CISA BOD 22-01's must-patch bar). Records a `promote`.
		if h.escalateKEV && f.Severity.Rank() < types.SeverityHigh.Rank() {
			from := f.Severity
			f.Severity = types.SeverityHigh
			return f, []types.AuditEntry{{
				FindingID:    f.ID,
				Action:       "promote",
				FromSeverity: from,
				ToSeverity:   types.SeverityHigh,
				Rule:         "threat_intel::kev-escalate",
				Reason:       cve + " is on the CISA KEV catalog (added " + kevDate(ti.KEV) + ") — actively exploited, bumped to high per BOD 22-01",
			}}, true
		}
		// Default: annotate only — log the KEV listing so the compliance audience sees the SLA-clock trigger.
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
