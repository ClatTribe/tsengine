// Package coverage answers "what was actually tested?" per asset — the visibility the industry says
// most teams lack ("52% of organizations don't have full visibility into what was tested",
// State-of-AI-in-Pentesting). A pentest you can't see into is one you have to take on trust; this turns
// each asset into an explicit, grounded statement of what the engine runs on it, when it last ran, and
// which tools surfaced something. Coverage knows the DECLARED toolset, not which tools executed.
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

// ConfigGatedClass is a vulnerability class the anchor pass CANNOT test on its own — it needs an
// operator-declared configuration (two identities to compare, a login flow to get behind). Until that
// config exists, the class is not tested, and a scan that reports nothing has not cleared it.
type ConfigGatedClass struct {
	Class       string `json:"class"`
	Reference   string `json:"reference,omitempty"`    // e.g. "OWASP API1"
	NeedsConfig string `json:"needs_config"`           // the Asset.Meta key that unlocks it
	ConfigureAt string `json:"configure_at,omitempty"` // the API that sets it
}

// configGated is the per-type table of classes that require operator configuration. Deliberately
// conservative: it lists ONLY classes whose gate is a config key readable from Asset.Meta, so the
// answer is grounded in stored state rather than inferred. Classes gated on something else (an L2
// agent having run, load generation) are NOT claimed here — an honest short list beats a speculative
// long one.
var configGated = map[string][]ConfigGatedClass{
	"api": {
		{Class: "Broken object level authorization (BOLA/IDOR)", Reference: "OWASP API1", NeedsConfig: "authz_test", ConfigureAt: "POST /v1/assets/{id}/authz-test"},
		{Class: "Broken function level authorization (BFLA)", Reference: "OWASP API5", NeedsConfig: "authz_test", ConfigureAt: "POST /v1/assets/{id}/authz-test"},
		{Class: "Cross-user broken authentication", Reference: "OWASP API2", NeedsConfig: "authz_test", ConfigureAt: "POST /v1/assets/{id}/authz-test"},
	},
	"web_application": {
		{Class: "Everything behind the login (authenticated surface)", NeedsConfig: "login_flow", ConfigureAt: "POST /v1/assets/{id}/login-flow"},
	},
}

// untestedClasses returns the config-gated classes this asset has NOT unlocked. Grounded (§10): a class
// is listed only when its config key is genuinely absent from the asset's stored Meta — a configured
// asset reports nothing here, so the list shrinks as the customer configures, never as a default.
func untestedClasses(a platform.Asset) []ConfigGatedClass {
	var out []ConfigGatedClass
	for _, c := range configGated[a.Type] {
		if strings.TrimSpace(a.Meta[c.NeedsConfig]) == "" {
			out = append(out, c)
		}
	}
	return out
}

// AssetCoverage is the per-asset "what was tested" statement.
type AssetCoverage struct {
	AssetID       string    `json:"asset_id"`
	Target        string    `json:"target"`
	Type          string    `json:"type"`
	Scanned       bool      `json:"scanned"` // has this asset ever completed a scan?
	LastScannedAt time.Time `json:"last_scanned_at,omitempty"`
	// RunsTools is the anchor toolset DECLARED for this asset type — what a scan of this type is
	// configured to run. It is not evidence that each tool executed on this asset.
	RunsTools []string `json:"runs_tools"`
	// ToolsWithFindings is which of them surfaced a finding. The remainder either ran and found
	// nothing OR never ran — coverage cannot tell the two apart, so it must not claim either.
	ToolsWithFindings []string `json:"tools_with_findings"`
	// ExecutionConfirmed reports whether per-tool execution was verified for this asset. It is
	// true when the scan's engagement recorded its dispatched toolset (runner.ReportingScanRunner).
	// False means execution was not reported — RunsTools is then the DECLARED list and nothing may
	// be concluded about whether each tool ran.
	//
	// This field exists so the UI states what is known rather than the reassuring version. A scan
	// that loses every tool to per-tool timeouts, or runs against an image where the tool is a stub
	// (a TOOLSET-limited build answers "prowler: not found"), produces zero findings and, before
	// this, was reported to the customer as "All tools ran and found nothing".
	ExecutionConfirmed bool `json:"execution_confirmed"`
	// ToolsFailed lists tools this scan dispatched that produced no result — a per-tool timeout, a
	// sandbox error, or a tool absent from a TOOLSET-limited image. Populated only when
	// ExecutionConfirmed is true.
	ToolsFailed   []types.ToolFailure `json:"tools_failed,omitempty"`
	FindingsCount int                 `json:"findings_count"`
	// UntestedClasses names the vulnerability classes this asset's scan CANNOT reach without an
	// operator-declared config that is currently absent. It exists because "we ran the tools and
	// found nothing" reads as "you are clean", and for an API that is the wrong conclusion: BOLA,
	// BFLA and cross-user auth (the top OWASP API risks) are business-logic classes no anchor tool
	// can test without two declared identities to compare. Reporting zero findings while silently
	// skipping them is the asset-level form of the "Clear on unscanned scope" overclaim — the engine
	// is honest about it (the fixtures record these as NOT COVERED), so the customer-facing surface
	// must be too.
	UntestedClasses []ConfigGatedClass `json:"untested_classes,omitempty"`
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
	// latest completed scan per asset, and what that scan actually dispatched
	lastScan := map[string]time.Time{}
	lastEng := map[string]platform.Engagement{}
	for _, e := range engagements {
		if e.CompletedAt.IsZero() {
			continue
		}
		if cur, ok := lastScan[e.AssetID]; !ok || e.CompletedAt.After(cur) {
			lastScan[e.AssetID] = e.CompletedAt
			lastEng[e.AssetID] = e
		}
	}

	out := Summary{TotalAssets: len(assets)}
	for _, a := range assets {
		cov := AssetCoverage{AssetID: a.ID, Target: a.Target, Type: a.Type, RunsTools: Toolset[a.Type], UntestedClasses: untestedClasses(a)}
		if cov.RunsTools == nil {
			cov.RunsTools = []string{} // honest empty, not null (an asset type with no declared anchors)
		}
		if t, ok := lastScan[a.ID]; ok {
			cov.Scanned = true
			cov.LastScannedAt = t
			out.ScannedAssets++

			// Prefer what the scan REALLY dispatched over the declared toolset. A runner that
			// reports nothing (the operate path dispatches no sandbox tools) leaves ToolsRan empty,
			// which stays "unknown" — the declared list, ExecutionConfirmed false — rather than
			// being read as "nothing ran".
			if e := lastEng[a.ID]; len(e.ToolsRan) > 0 {
				cov.RunsTools = append([]string{}, e.ToolsRan...)
				sort.Strings(cov.RunsTools)
				cov.ToolsFailed = e.ToolsFailed
				cov.ExecutionConfirmed = true
			}
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
