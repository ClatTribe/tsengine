// Package coverage answers "what was actually tested?" per asset — the visibility the industry says
// most teams lack ("52% of organizations don't have full visibility into what was tested",
// State-of-AI-in-Pentesting). A pentest you can't see into is one you have to take on trust; this turns
// each asset into an explicit, grounded statement of what the engine runs on it, when it last ran, and
// which tools surfaced something (the rest ran clean).
//
// Grounded (§10): the per-type toolset is the DECLARED anchor tier — the tools that fire deterministically
// on every scan of that type (§4.1), curated to mirror the asset modules. An asset that's never been
// scanned reports scanned:false (never "covered"); tools-with-findings is derived only from real findings
// attributed to the asset by a literal target match. No coverage is ever asserted that a scan didn't back.
package coverage

import (
	"sort"
	"strings"
	"time"

	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// Toolset is the declared anchor coverage per asset type — the OSS tools that fire on EVERY scan of that
// type (the §4.1 anchor tier is deterministic, so this is what actually runs, not a wish list). Registry-
// tier tools are on-demand and deliberately NOT listed here (they're surfaced separately as available
// depth). Mirrors the per-asset anchor tiers in the asset modules; keep in sync when an anchor changes.
var Toolset = map[string][]string{
	"web_application":    {"katana", "httpx", "nuclei", "dalfox", "sqlmap"},
	"api":                {"nuclei", "kiterunner", "inql"},
	"repository":         {"gitleaks", "trufflehog", "semgrep", "trivy", "grype"},
	"container_image":    {"trivy", "grype", "dockle", "cosign"},
	"ip_address":         {"naabu", "nmap", "httpx", "nuclei"},
	"domain":             {"subfinder", "amass", "dnstwist", "httpx"},
	"cloud_account":      {"prowler"},
	"mobile_application": {"mobsfscan", "gitleaks", "trufflehog", "semgrep", "trivy", "apkid"},
	"workspace":          {"identity posture (MFA · OAuth grants · email-auth · stale accounts)"},
}

// AssetCoverage is the per-asset "what was tested" statement.
type AssetCoverage struct {
	AssetID           string    `json:"asset_id"`
	Target            string    `json:"target"`
	Type              string    `json:"type"`
	Scanned           bool      `json:"scanned"` // has this asset ever completed a scan?
	LastScannedAt     time.Time `json:"last_scanned_at,omitempty"`
	RunsTools         []string  `json:"runs_tools"`          // the anchor tools every scan of this type runs
	ToolsWithFindings []string  `json:"tools_with_findings"` // which of them surfaced a finding (rest ran clean)
	FindingsCount     int       `json:"findings_count"`
}

// Summary rolls up coverage across the portfolio for a headline ("N of M assets scanned").
type Summary struct {
	Assets        []AssetCoverage `json:"assets"`
	TotalAssets   int             `json:"total_assets"`
	ScannedAssets int             `json:"scanned_assets"`
}

// Compute builds the per-asset coverage from the grounded record: the declared anchor toolset for each
// asset's type, the asset's last completed engagement (when it was scanned), and the tools that produced
// findings attributed to it. Deterministic + LLM-free.
func Compute(assets []platform.Asset, findings []types.Finding, engagements []platform.Engagement) Summary {
	// latest completed scan per asset
	lastScan := map[string]time.Time{}
	for _, e := range engagements {
		if e.CompletedAt.IsZero() {
			continue
		}
		if cur, ok := lastScan[e.AssetID]; !ok || e.CompletedAt.After(cur) {
			lastScan[e.AssetID] = e.CompletedAt
		}
	}

	out := Summary{TotalAssets: len(assets)}
	for _, a := range assets {
		cov := AssetCoverage{AssetID: a.ID, Target: a.Target, Type: a.Type, RunsTools: Toolset[a.Type]}
		if cov.RunsTools == nil {
			cov.RunsTools = []string{} // honest empty, not null (an asset type with no declared anchors)
		}
		if t, ok := lastScan[a.ID]; ok {
			cov.Scanned = true
			cov.LastScannedAt = t
			out.ScannedAssets++
		}
		// tools that surfaced a finding attributed to THIS asset (grounded: literal target match)
		seen := map[string]bool{}
		for _, f := range findings {
			if attribute(f, assets) != a.ID || f.Tool == "" {
				continue
			}
			cov.FindingsCount++
			if !seen[f.Tool] {
				seen[f.Tool] = true
				cov.ToolsWithFindings = append(cov.ToolsWithFindings, f.Tool)
			}
		}
		sort.Strings(cov.ToolsWithFindings)
		out.Assets = append(out.Assets, cov)
	}
	return out
}

// attribute returns the id of the asset whose Target literally appears in the finding's endpoint (longest
// match wins — the same grounded attribution as data-tier / per-asset compliance). "" when none matches
// (e.g. a repo file:line endpoint with no asset target in it) — never guessed.
func attribute(f types.Finding, assets []platform.Asset) string {
	best, bestLen := "", 0
	for _, a := range assets {
		if a.Target != "" && len(a.Target) > bestLen && strings.Contains(f.Endpoint, a.Target) {
			best, bestLen = a.ID, len(a.Target)
		}
	}
	return best
}
