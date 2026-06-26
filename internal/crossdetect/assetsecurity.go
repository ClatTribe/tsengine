package crossdetect

import (
	"fmt"
	"sort"
	"strings"

	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// AssetSecurity is the per-asset security posture — the "is THIS asset secure?" view a daily-driver user
// needs, answered honestly and FP-aware. It rolls each finding up to the asset whose Target literally
// appears in its endpoint (grounded §10 — never a fabricated link), and separates CONFIRMED findings
// (verified or corroborated by ≥2 tools — trust these) from UNCONFIRMED ones (single-tool pattern_match —
// confirm before acting), so a wall of low-confidence noise never reads as "this asset is on fire". The
// verdict NEVER says a bare "secure": a clean-but-scanned asset is "no issues found in the last scan" (an
// auditor/pentest proves secure, a scan doesn't), and an un-scanned/un-attributed asset says so.
type AssetSecurity struct {
	AssetID       string `json:"asset_id"`
	Target        string `json:"target"`
	Type          string `json:"type"`
	Scanned       bool   `json:"scanned"`     // has this asset been scanned at least once? (coverage)
	Attributed    bool   `json:"attributed"`  // is any finding tied to it?
	Findings      int    `json:"findings"`    // attributed findings
	Confirmed     int    `json:"confirmed"`   // verified or corroborated — FP-controlled, act on these
	Unconfirmed   int    `json:"unconfirmed"` // single-tool pattern_match — confirm before acting
	Critical      int    `json:"critical"`
	High          int    `json:"high"`
	WorstSeverity string `json:"worst_severity"`
	Verdict       string `json:"verdict"` // honest one-liner — NEVER a bare "secure"
}

// AssetSecurityPosture returns the per-asset security posture. scanned[assetID]=true marks assets that have
// at least one completed scan (so "no findings" can read as "clean in the last scan" vs "not yet scanned").
func AssetSecurityPosture(assets []platform.Asset, findings []types.Finding, scanned map[string]bool) []AssetSecurity {
	type acc struct {
		n, confirmed, unconfirmed, crit, high int
		worst                                 types.Severity
		seen                                  bool
	}
	accs := make(map[string]*acc, len(assets))
	for _, a := range assets {
		accs[a.ID] = &acc{}
	}

	for _, f := range findings {
		if f.Endpoint == "" {
			continue
		}
		id := assetIDForEndpoint(f.Endpoint, assets)
		if id == "" {
			continue
		}
		ac := accs[id]
		ac.n++
		if isConfirmed(f.VerificationStatus) {
			ac.confirmed++
		} else {
			ac.unconfirmed++
		}
		switch f.Severity {
		case types.SeverityCritical:
			ac.crit++
		case types.SeverityHigh:
			ac.high++
		}
		if !ac.seen || severityBase(f.Severity) > severityBase(ac.worst) {
			ac.worst, ac.seen = f.Severity, true
		}
	}

	out := make([]AssetSecurity, 0, len(assets))
	for _, a := range assets {
		ac := accs[a.ID]
		p := AssetSecurity{
			AssetID: a.ID, Target: a.Target, Type: a.Type,
			Scanned: scanned[a.ID], Attributed: ac.n > 0, Findings: ac.n,
			Confirmed: ac.confirmed, Unconfirmed: ac.unconfirmed, Critical: ac.crit, High: ac.high,
		}
		if ac.seen {
			p.WorstSeverity = string(ac.worst)
		}
		p.Verdict = securityVerdict(p)
		out = append(out, p)
	}
	// Worst posture first: confirmed-high assets lead, then by finding count, then attributed, then target.
	sort.SliceStable(out, func(i, j int) bool {
		ri, rj := riskRank(out[i]), riskRank(out[j])
		if ri != rj {
			return ri > rj
		}
		if out[i].Findings != out[j].Findings {
			return out[i].Findings > out[j].Findings
		}
		if out[i].Attributed != out[j].Attributed {
			return out[i].Attributed
		}
		return out[i].Target < out[j].Target
	})
	return out
}

// securityVerdict is the honest, FP-aware per-asset line — never a bare "secure".
func securityVerdict(p AssetSecurity) string {
	confirmedHigh := p.Critical + p.High // counted across all attributed; refined below by confirmation
	switch {
	case !p.Attributed && !p.Scanned:
		return "Not yet scanned"
	case !p.Attributed:
		return "No issues found in the last scan — not a guarantee it's secure"
	case p.Confirmed > 0 && confirmedHigh > 0:
		return fmt.Sprintf("At risk — %d confirmed high-impact issue%s to fix now", confirmedHigh, plural(confirmedHigh))
	case p.Confirmed > 0:
		return fmt.Sprintf("%d confirmed issue%s to review", p.Confirmed, plural(p.Confirmed))
	default:
		return fmt.Sprintf("%d unconfirmed finding%s — confirm before acting", p.Unconfirmed, plural(p.Unconfirmed))
	}
}

// riskRank buckets an asset for ordering: confirmed-high = most urgent.
func riskRank(p AssetSecurity) int {
	switch {
	case p.Confirmed > 0 && (p.Critical+p.High) > 0:
		return 4
	case p.Confirmed > 0:
		return 3
	case p.Unconfirmed > 0:
		return 2
	case p.Scanned:
		return 1 // scanned-clean ranks above never-scanned
	default:
		return 0
	}
}

func isConfirmed(v types.VerificationState) bool {
	return v == types.VerificationVerified || v == types.VerificationCorroborated
}

// assetIDForEndpoint returns the id of the asset whose non-empty Target is contained in endpoint, longest
// Target winning. "" when none matches — never a guessed attribution (§10). Mirrors tierForEndpoint.
func assetIDForEndpoint(endpoint string, assets []platform.Asset) string {
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

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}
