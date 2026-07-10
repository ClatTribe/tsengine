package importers

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/ClatTribe/tsengine/internal/reachability"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// Format identifies a supported input format.
type Format string

const (
	FormatAuto       Format = "auto"
	FormatSARIF      Format = "sarif"
	FormatSnyk       Format = "snyk"
	FormatDependabot Format = "dependabot" // GitHub Dependabot alerts JSON (GHAS)
)

// Detect sniffs the format from the payload shape.
func Detect(data []byte) Format {
	trimmed := strings.TrimSpace(string(data))
	// GitHub Dependabot alerts is a JSON array of objects with security_advisory.
	if strings.HasPrefix(trimmed, "[") && strings.Contains(trimmed, "security_advisory") {
		return FormatDependabot
	}
	var probe map[string]json.RawMessage
	if json.Unmarshal(data, &probe) == nil {
		if _, ok := probe["runs"]; ok {
			return FormatSARIF
		}
		if _, ok := probe["vulnerabilities"]; ok {
			return FormatSnyk
		}
	}
	return FormatAuto
}

// Import normalizes any supported scanner output into a types.Scan (consumed by
// report / findings DB / gate). format may be FormatAuto.
func Import(data []byte, format Format, target string, now time.Time) (types.Scan, error) {
	if format == "" || format == FormatAuto {
		format = Detect(data)
	}
	switch format {
	case FormatSARIF:
		return FromSARIF(data, target, now)
	case FormatSnyk:
		return FromSnyk(data, target, now)
	case FormatDependabot:
		return FromDependabot(data, target, now)
	default:
		return types.Scan{}, fmt.Errorf("import: unrecognized format (not SARIF, Snyk, or Dependabot)")
	}
}

// ImportSCA extracts reachability-ready SCA findings from a dependency scanner's
// output (Snyk or Dependabot). SARIF SAST results are not dependency findings.
func ImportSCA(data []byte, format Format) ([]reachability.SCAFinding, error) {
	if format == "" || format == FormatAuto {
		format = Detect(data)
	}
	switch format {
	case FormatSnyk:
		return SnykToSCA(data)
	case FormatDependabot:
		return DependabotToSCA(data)
	default:
		return nil, fmt.Errorf("import-sca: %q is not a dependency-scanner format (use snyk or dependabot)", format)
	}
}

// --- GitHub Dependabot alerts (GHAS) ---

type dependabotAlert struct {
	Number           int    `json:"number"`
	State            string `json:"state"`
	SecurityAdvisory struct {
		Summary  string `json:"summary"`
		Severity string `json:"severity"`
		CVEID    string `json:"cve_id"`
		CWEs     []struct {
			CWEID string `json:"cwe_id"`
		} `json:"cwes"`
	} `json:"security_advisory"`
	SecurityVulnerability struct {
		Package struct {
			Name      string `json:"name"`
			Ecosystem string `json:"ecosystem"`
		} `json:"package"`
		VulnerableVersionRange string `json:"vulnerable_version_range"`
	} `json:"security_vulnerability"`
	Dependency struct {
		ManifestPath string `json:"manifest_path"`
	} `json:"dependency"`
}

// FromDependabot parses the GitHub Dependabot alerts API array into a types.Scan.
func FromDependabot(data []byte, target string, now time.Time) (types.Scan, error) {
	alerts, err := parseDependabot(data)
	if err != nil {
		return types.Scan{}, err
	}
	scan := newScan("repository", firstNonEmpty(target, "github-repo"), now)
	scan.AnchorsFired = []string{"dependabot"}
	for i, a := range alerts {
		if a.State != "" && a.State != "open" {
			continue // only open alerts
		}
		var cwe []string
		for _, c := range a.SecurityAdvisory.CWEs {
			if c.CWEID != "" {
				cwe = append(cwe, strings.ToUpper(c.CWEID))
			}
		}
		f := types.Finding{
			ID:              fmt.Sprintf("imp-ghas-%04d", i+1),
			RuleID:          "dependabot::" + firstNonEmpty(a.SecurityAdvisory.CVEID, fmt.Sprintf("alert-%d", a.Number)),
			Tool:            "dependabot",
			Severity:        normSeverity(a.SecurityAdvisory.Severity),
			Title:           firstNonEmpty(a.SecurityAdvisory.Summary, a.SecurityAdvisory.CVEID),
			Description:     a.SecurityAdvisory.CVEID + " in " + a.SecurityVulnerability.Package.Name + " " + a.SecurityVulnerability.VulnerableVersionRange,
			Endpoint:        a.SecurityVulnerability.Package.Name,
			CWE:             cwe,
			DiscoveredAt:    now,
			DiscoveryMethod: &types.DiscoveryMethod{Primary: "imported:dependabot"},
		}
		scan.FindingsRaw = append(scan.FindingsRaw, f)
	}
	scan.FindingsEnriched = scan.FindingsRaw
	return scan, nil
}

// DependabotToSCA extracts reachability-ready SCA findings.
func DependabotToSCA(data []byte) ([]reachability.SCAFinding, error) {
	alerts, err := parseDependabot(data)
	if err != nil {
		return nil, err
	}
	var out []reachability.SCAFinding
	for _, a := range alerts {
		if a.State != "" && a.State != "open" {
			continue
		}
		out = append(out, reachability.SCAFinding{
			ID:        firstNonEmpty(a.SecurityAdvisory.CVEID, fmt.Sprintf("ghsa-%d", a.Number)),
			CVE:       a.SecurityAdvisory.CVEID,
			Package:   a.SecurityVulnerability.Package.Name,
			Severity:  strings.ToLower(a.SecurityAdvisory.Severity),
			Ecosystem: a.SecurityVulnerability.Package.Ecosystem, // GHAS: npm|pip|go|maven|… → routes reachability
		})
	}
	return out, nil
}

func parseDependabot(data []byte) ([]dependabotAlert, error) {
	var alerts []dependabotAlert
	if err := json.Unmarshal(data, &alerts); err != nil {
		return nil, fmt.Errorf("dependabot: %w", err)
	}
	return alerts, nil
}

// --- shared helpers ---

func newScan(assetType, target string, now time.Time) types.Scan {
	return types.Scan{
		ScanID:      "import-" + now.Format("20060102T150405Z"),
		Asset:       types.Asset{Type: types.AssetType(assetType), Target: target},
		StartedAt:   now,
		CompletedAt: now,
		Engine:      types.Engine{Version: "tsengine-import"},
	}
}

func normSeverity(s string) types.Severity {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return types.SeverityCritical
	case "high":
		return types.SeverityHigh
	case "medium", "moderate":
		return types.SeverityMedium
	case "low":
		return types.SeverityLow
	case "info", "informational", "none":
		return types.SeverityInfo
	}
	return types.SeverityInfo
}

func firstNonEmpty(xs ...string) string {
	for _, x := range xs {
		if strings.TrimSpace(x) != "" {
			return x
		}
	}
	return ""
}

func short(s string) string {
	s = strings.ToLower(s)
	var b strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		}
		if b.Len() >= 6 {
			break
		}
	}
	if b.Len() == 0 {
		return "tool"
	}
	return b.String()
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}
