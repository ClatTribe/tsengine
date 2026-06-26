package grc

import (
	"sort"
	"strings"

	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// AssetPosture is one asset's grounded compliance signal — the "is THIS asset compliant?" view competitors
// (Vanta) show per-resource. A finding maps to an asset only when the asset's non-empty Target literally
// appears in the finding's Endpoint (longest Target wins), so attribution is never fabricated (§10). Each
// attributed finding's compliance annotation = a gap on the controls it cites; we tally distinct
// (framework, control) pairs. Assets we can't attribute (repo file:line endpoints, no finding→asset link in
// the data model yet) come back Attributed=false with zero counts — honest, never a false "compliant".
type AssetPosture struct {
	AssetID       string   `json:"asset_id"`
	Target        string   `json:"target"`
	Type          string   `json:"type"`
	Attributed    bool     `json:"attributed"`     // could we tie ANY finding to this asset's target?
	FindingCount  int      `json:"finding_count"`  // attributed findings
	GapControls   int      `json:"gap_controls"`   // distinct (framework, control) pairs those findings cite
	Frameworks    []string `json:"frameworks"`     // distinct frameworks those findings touch (sorted)
	WorstSeverity string   `json:"worst_severity"` // worst attributed severity, "" when none
	Status        string   `json:"status"`         // honest one-liner — NEVER the word "compliant"
}

// AssetCompliancePosture rolls each tenant finding up to the asset it touches and returns a per-asset
// compliance signal. Pure + grounded: attribution is endpoint-contains-target only; an asset with no
// attributable finding is reported as "not attributed", never as compliant.
func AssetCompliancePosture(assets []platform.Asset, findings []types.Finding) []AssetPosture {
	type acc struct {
		count    int
		controls map[string]struct{} // "framework|control" keys
		frames   map[string]struct{}
		worst    types.Severity
		seenSev  bool
	}
	accs := make(map[string]*acc, len(assets))
	for _, a := range assets {
		accs[a.ID] = &acc{controls: map[string]struct{}{}, frames: map[string]struct{}{}}
	}

	for _, f := range findings {
		if f.Endpoint == "" {
			continue
		}
		id := bestAssetForEndpoint(f.Endpoint, assets)
		if id == "" {
			continue
		}
		ac := accs[id]
		ac.count++
		if !ac.seenSev || severityRank(f.Severity) > severityRank(ac.worst) {
			ac.worst, ac.seenSev = f.Severity, true
		}
		for frame, ctrls := range complianceControls(f.Compliance) {
			ac.frames[frame] = struct{}{}
			for _, c := range ctrls {
				ac.controls[frame+"|"+c] = struct{}{}
			}
		}
	}

	out := make([]AssetPosture, 0, len(assets))
	for _, a := range assets {
		ac := accs[a.ID]
		frames := make([]string, 0, len(ac.frames))
		for fr := range ac.frames {
			frames = append(frames, fr)
		}
		sort.Strings(frames)
		p := AssetPosture{
			AssetID: a.ID, Target: a.Target, Type: a.Type,
			Attributed: ac.count > 0, FindingCount: ac.count,
			GapControls: len(ac.controls), Frameworks: frames,
		}
		if ac.seenSev {
			p.WorstSeverity = string(ac.worst)
		}
		p.Status = assetStatus(p)
		out = append(out, p)
	}
	// Worst posture first (most gaps, then most findings), then attributed-before-not, then target.
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].GapControls != out[j].GapControls {
			return out[i].GapControls > out[j].GapControls
		}
		if out[i].FindingCount != out[j].FindingCount {
			return out[i].FindingCount > out[j].FindingCount
		}
		if out[i].Attributed != out[j].Attributed {
			return out[i].Attributed
		}
		return out[i].Target < out[j].Target
	})
	return out
}

// assetStatus is the honest per-asset line. It NEVER says "compliant" — a clean attributed asset is only
// "no automated gaps" (an auditor attests compliance), and a non-attributed asset is explicit about why.
func assetStatus(p AssetPosture) string {
	if !p.Attributed {
		return "No findings tied to this asset yet — not assessed at the asset level"
	}
	if p.GapControls > 0 {
		return "Has open control gaps — not compliant until they're closed"
	}
	return "No automated control gaps — not a certification"
}

// bestAssetForEndpoint returns the id of the asset whose non-empty Target is contained in endpoint, longest
// Target winning (a specific path-asset beats its parent host). "" when none matches — never a guess.
func bestAssetForEndpoint(endpoint string, assets []platform.Asset) string {
	best, bestLen := "", 0
	for _, a := range assets {
		if a.Target == "" || len(a.Target) <= bestLen {
			continue
		}
		if strings.Contains(endpoint, a.Target) {
			best, bestLen = a.ID, len(a.Target)
		}
	}
	return best
}

func severityRank(s types.Severity) int {
	switch s {
	case types.SeverityCritical:
		return 5
	case types.SeverityHigh:
		return 4
	case types.SeverityMedium:
		return 3
	case types.SeverityLow:
		return 2
	case types.SeverityInfo:
		return 1
	}
	return 0
}

// complianceControls flattens a finding's compliance annotation into framework→controls. Enumerated
// explicitly over the 22-framework set (CLAUDE.md §8) — the same grounded mirror discipline as the rest of
// the crosswalk; a new framework adds one line here.
func complianceControls(c *types.Compliance) map[string][]string {
	if c == nil {
		return nil
	}
	m := map[string][]string{}
	add := func(name string, v []string) {
		if len(v) > 0 {
			m[name] = v
		}
	}
	add("soc2", c.SOC2)
	add("pci", c.PCI)
	add("hipaa", c.HIPAA)
	add("cis_v8", c.CISv8)
	add("nist_csf", c.NISTCSF)
	add("iso27001", c.ISO27001)
	add("gdpr", c.GDPR)
	add("iso27701", c.ISO27701)
	add("nist_800_53", c.NIST80053)
	add("nist_800_171", c.NIST800171)
	add("ccpa", c.CCPA)
	add("sox", c.SOX)
	add("fedramp", c.FedRAMP)
	add("dpdp", c.DPDP)
	add("cmmc", c.CMMC)
	add("iso42001", c.ISO42001)
	add("nist_ai_rmf", c.NISTAIRMF)
	add("iso27018", c.ISO27018)
	add("iso22301", c.ISO22301)
	add("pipeda", c.PIPEDA)
	add("glba", c.GLBA)
	add("eu_ai_act", c.EUAIAct)
	return m
}
