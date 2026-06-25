package hooks

import (
	_ "embed"
	"encoding/json"
	"sort"

	"github.com/ClatTribe/tsengine/pkg/types"
)

//go:embed data/compliance.json
var complianceCorpus []byte

// Compliance implements hook 7 of CLAUDE.md §11 + §8. For each CWE on a
// finding it looks up the affected compliance controls (SOC2 / PCI /
// HIPAA / CIS / NIST) from the embedded corpus and merges them into a
// Compliance annotation.
//
// Mapping is annotation, not gate: the finding is emitted regardless;
// this just records which controls it touches. No L1 tool DECIDES a
// SOC2 violation — it emits the technical finding, this maps it.
type Compliance struct {
	corpus map[string]controlSet
}

type controlSet struct {
	SOC2       []string `json:"soc2"`
	PCI        []string `json:"pci"`
	HIPAA      []string `json:"hipaa"`
	CISv8      []string `json:"cis_v8"`
	NISTCSF    []string `json:"nist_csf"`
	ISO27001   []string `json:"iso27001"`
	GDPR       []string `json:"gdpr"`
	ISO27701   []string `json:"iso27701"`
	NIST80053  []string `json:"nist_800_53"`
	NIST800171 []string `json:"nist_800_171"`
	CCPA       []string `json:"ccpa"`
	SOX        []string `json:"sox"`
	FedRAMP    []string `json:"fedramp"`
	DPDP       []string `json:"dpdp"`
}

// NewCompliance loads the embedded corpus. Panics on malformed data.
func NewCompliance() *Compliance {
	var c map[string]controlSet
	if err := json.Unmarshal(complianceCorpus, &c); err != nil {
		panic("hooks: malformed embedded compliance corpus: " + err.Error())
	}
	return &Compliance{corpus: c}
}

func (*Compliance) Name() string { return "compliance" }

// ControlsFor returns the distinct, sorted set of controls a framework defines across the whole
// crosswalk — i.e. the controls this engine can actually assess for that framework (the ones it maps
// findings to). Used to seed an audit engagement's control checklist for a tenant that has no posture
// yet (a fresh account): grounded (§10) — these are real controls the product speaks to, not a guessed
// or padded catalog. Framework key matches grc.Frameworks (soc2, pci, hipaa, …). Unknown key → nil.
func (h *Compliance) ControlsFor(framework string) []string {
	seen := map[string]bool{}
	for _, cs := range h.corpus {
		for _, id := range cs.forFramework(framework) {
			seen[id] = true
		}
	}
	if len(seen) == 0 {
		return nil // unknown framework / no mapped controls — never a guessed catalog
	}
	out := make([]string, 0, len(seen))
	for id := range seen {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// forFramework selects this CWE's control list for a framework key.
func (cs controlSet) forFramework(framework string) []string {
	switch framework {
	case "soc2":
		return cs.SOC2
	case "pci":
		return cs.PCI
	case "hipaa":
		return cs.HIPAA
	case "cis_v8":
		return cs.CISv8
	case "nist_csf":
		return cs.NISTCSF
	case "iso27001":
		return cs.ISO27001
	case "gdpr":
		return cs.GDPR
	case "iso27701":
		return cs.ISO27701
	case "nist_800_53":
		return cs.NIST80053
	case "nist_800_171":
		return cs.NIST800171
	case "ccpa":
		return cs.CCPA
	case "sox":
		return cs.SOX
	case "fedramp":
		return cs.FedRAMP
	case "dpdp":
		return cs.DPDP
	}
	return nil
}

// Lookup maps a set of CWEs to the union of compliance controls they affect,
// or (nil,false) if none match. Single corpus access path, shared by the
// L1.5 Apply hook AND the L2 lookup_compliance_mapping adapter
// (internal/l2/adapters) — one corpus, one mapping.
func (h *Compliance) Lookup(cwes []string) (*types.Compliance, bool) {
	agg := &types.Compliance{}
	matched := false
	for _, cwe := range cwes {
		cs, ok := h.corpus[cwe]
		if !ok {
			continue
		}
		matched = true
		agg.SOC2 = mergeUnique(agg.SOC2, cs.SOC2)
		agg.PCI = mergeUnique(agg.PCI, cs.PCI)
		agg.HIPAA = mergeUnique(agg.HIPAA, cs.HIPAA)
		agg.CISv8 = mergeUnique(agg.CISv8, cs.CISv8)
		agg.NISTCSF = mergeUnique(agg.NISTCSF, cs.NISTCSF)
		agg.ISO27001 = mergeUnique(agg.ISO27001, cs.ISO27001)
		agg.GDPR = mergeUnique(agg.GDPR, cs.GDPR)
		agg.ISO27701 = mergeUnique(agg.ISO27701, cs.ISO27701)
		agg.NIST80053 = mergeUnique(agg.NIST80053, cs.NIST80053)
		agg.NIST800171 = mergeUnique(agg.NIST800171, cs.NIST800171)
		agg.CCPA = mergeUnique(agg.CCPA, cs.CCPA)
		agg.SOX = mergeUnique(agg.SOX, cs.SOX)
		agg.FedRAMP = mergeUnique(agg.FedRAMP, cs.FedRAMP)
		agg.DPDP = mergeUnique(agg.DPDP, cs.DPDP)
	}
	if !matched {
		return nil, false
	}
	return agg, true
}

// Apply maps the finding's CWEs to controls. Annotation-only.
func (h *Compliance) Apply(f types.Finding) (types.Finding, []types.AuditEntry, bool) {
	if len(f.CWE) == 0 {
		return f, nil, true
	}
	agg, ok := h.Lookup(f.CWE)
	if !ok {
		return f, nil, true
	}
	f.Compliance = agg
	return f, nil, true
}

// mergeUnique appends src into dst, dropping duplicates while preserving
// first-seen order. Keeps annotation deterministic for reproducibility.
func mergeUnique(dst, src []string) []string {
	if len(src) == 0 {
		return dst
	}
	seen := make(map[string]struct{}, len(dst))
	for _, v := range dst {
		seen[v] = struct{}{}
	}
	for _, v := range src {
		if _, dup := seen[v]; dup {
			continue
		}
		seen[v] = struct{}{}
		dst = append(dst, v)
	}
	return dst
}
