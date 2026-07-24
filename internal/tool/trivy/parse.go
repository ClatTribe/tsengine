package trivy

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/ClatTribe/tsengine/pkg/types"
)

// report mirrors the relevant subset of `trivy --format json` output.
// The full schema is large; we only project what tsengine surfaces.
type report struct {
	ArtifactName string   `json:"ArtifactName"`
	ArtifactType string   `json:"ArtifactType"`
	Results      []result `json:"Results"`
}

type result struct {
	Target            string          `json:"Target"`
	Class             string          `json:"Class"`
	Type              string          `json:"Type"`
	Vulnerabilities   []vulnerability `json:"Vulnerabilities"`
	Misconfigurations []misconfig     `json:"Misconfigurations"`
	Secrets           []secret        `json:"Secrets"`
}

type vulnerability struct {
	VulnerabilityID  string   `json:"VulnerabilityID"`
	PkgName          string   `json:"PkgName"`
	InstalledVersion string   `json:"InstalledVersion"`
	FixedVersion     string   `json:"FixedVersion"`
	Status           string   `json:"Status"` // fixed | affected | will_not_fix | fix_deferred | end_of_life
	Severity         string   `json:"Severity"`
	Title            string   `json:"Title"`
	Description      string   `json:"Description"`
	CweIDs           []string `json:"CweIDs"`
	PrimaryURL       string   `json:"PrimaryURL"`
	References       []string `json:"References"`
}

type misconfig struct {
	ID          string `json:"ID"`
	AVDID       string `json:"AVDID"`
	Title       string `json:"Title"`
	Description string `json:"Description"`
	Severity    string `json:"Severity"`
	Resolution  string `json:"Resolution"`
}

type secret struct {
	RuleID    string `json:"RuleID"`
	Category  string `json:"Category"`
	Severity  string `json:"Severity"`
	Title     string `json:"Title"`
	StartLine int    `json:"StartLine"`
	EndLine   int    `json:"EndLine"`
	Match     string `json:"Match"`
}

// parseReport turns trivy's JSON output into a flat slice of
// SandboxEmittedFindings. Vulnerabilities + misconfigs + secrets are
// all flattened — the security-engineer audience reads them through
// the same per-tool dashboard, distinguishable by RuleID prefix.
func parseReport(blob []byte) []types.SandboxEmittedFinding {
	if len(blob) == 0 {
		return nil
	}
	var r report
	if err := json.Unmarshal(blob, &r); err != nil {
		return nil
	}

	var out []types.SandboxEmittedFinding
	for _, res := range r.Results {
		endpoint := res.Target
		if endpoint == "" {
			endpoint = r.ArtifactName
		}
		for _, v := range res.Vulnerabilities {
			out = append(out, vulnToFinding(v, endpoint, res.Class))
		}
		for _, m := range res.Misconfigurations {
			out = append(out, misconfToFinding(m, endpoint))
		}
		for _, s := range res.Secrets {
			out = append(out, secretToFinding(s, endpoint))
		}
	}
	return out
}

// normalizeFixState maps trivy's per-vuln Status to the tool-agnostic fix_state contract shared with
// grype. Only a distro DECISION not to fix (will_not_fix) or an unsupported release (end_of_life)
// becomes "wont-fix" (the unpatchable-noise signal); "affected"/"fix_deferred" (a fix may still land)
// stays actionable and is passed through verbatim.
// withFixNote appends a concise, grounded fix-availability line to a finding description — the
// competitor-parity "fixable vs no-fix" signal, immediately visible in the VAPT report / issue detail.
func withFixNote(desc, fixedVer string) string {
	if fixedVer != "" {
		return strings.TrimSpace(desc + "\nFix available: upgrade to " + fixedVer + ".")
	}
	return strings.TrimSpace(desc + "\nNo fixed version available yet — mitigate (pin/replace/isolate) until upstream patches.")
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

func normalizeFixState(status string) string {
	switch status {
	case "will_not_fix", "end_of_life":
		return "wont-fix"
	default:
		return status
	}
}

func vulnToFinding(v vulnerability, endpoint, class string) types.SandboxEmittedFinding {
	raw, _ := json.Marshal(v)
	title := v.Title
	if title == "" {
		title = fmt.Sprintf("%s in %s", v.VulnerabilityID, v.PkgName)
	}
	// The endpoint must identify the specific package, not just the
	// scanned artifact — otherwise the same CVE affecting two packages
	// (e.g. CVE-2022-1304 in both e2fslibs and libcom-err2) would share
	// (tool, rule_id, endpoint) and be wrongly collapsed by the L1.5
	// cross_tool_merge hook.
	pkgEndpoint := endpoint
	if v.PkgName != "" {
		pkgEndpoint = fmt.Sprintf("%s [%s@%s]", endpoint, v.PkgName, v.InstalledVersion)
	}
	return types.SandboxEmittedFinding{
		RuleID:          "trivy::" + v.VulnerabilityID,
		Tool:            "trivy",
		Severity:        normalizeSeverity(v.Severity),
		CWE:             v.CweIDs, // trivy already emits canonical CWE-N form
		Endpoint:        pkgEndpoint,
		Title:           title,
		Description:     withFixNote(v.Description, v.FixedVersion),
		RawOutput:       raw,
		MITRETechniques: []string{"T1195.002"}, // supply-chain-via-software-deps
		ToolArgs: map[string]string{
			"pkg":               v.PkgName,
			"installed_version": v.InstalledVersion,
			"fixed_version":     v.FixedVersion,
			"fixable":           boolStr(v.FixedVersion != ""), // competitor-parity fixable signal
			"primary_url":       v.PrimaryURL,
			"pkg_class":         class,                       // "os-pkgs" (distro) vs "lang-pkgs" (app dep)
			"fix_state":         normalizeFixState(v.Status), // tool-agnostic; "wont-fix" = distro won't patch
		},
	}
}

func misconfToFinding(m misconfig, endpoint string) types.SandboxEmittedFinding {
	raw, _ := json.Marshal(m)
	id := m.AVDID
	if id == "" {
		id = m.ID
	}
	return types.SandboxEmittedFinding{
		RuleID:          "trivy::misconfig::" + id,
		Tool:            "trivy",
		Severity:        normalizeSeverity(m.Severity),
		Endpoint:        endpoint,
		Title:           m.Title,
		Description:     strings.TrimSpace(m.Description + "\n" + m.Resolution),
		RawOutput:       raw,
		MITRETechniques: []string{"T1610"}, // deploy container with misconfig
	}
}

func secretToFinding(s secret, endpoint string) types.SandboxEmittedFinding {
	raw, _ := json.Marshal(s)
	loc := fmt.Sprintf("%s:%d-%d", endpoint, s.StartLine, s.EndLine)
	return types.SandboxEmittedFinding{
		RuleID:          "trivy::secret::" + s.RuleID,
		Tool:            "trivy",
		Severity:        normalizeSeverity(s.Severity),
		CWE:             []string{"CWE-798"}, // hardcoded credentials
		Endpoint:        loc,
		Title:           s.Title,
		RawOutput:       raw,
		MITRETechniques: []string{"T1552.001"}, // unsecured creds in files
	}
}

func normalizeSeverity(s string) types.Severity {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "CRITICAL":
		return types.SeverityCritical
	case "HIGH":
		return types.SeverityHigh
	case "MEDIUM":
		return types.SeverityMedium
	case "LOW":
		return types.SeverityLow
	case "UNKNOWN", "INFO", "":
		return types.SeverityInfo
	default:
		return types.SeverityInfo
	}
}
