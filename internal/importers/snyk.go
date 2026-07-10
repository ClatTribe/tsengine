package importers

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/ClatTribe/tsengine/internal/reachability"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// --- Snyk test JSON (SCA / dependency vulnerabilities) ---

type snykDoc struct {
	Vulnerabilities []snykVuln `json:"vulnerabilities"`
	ProjectName     string     `json:"projectName"`
	TargetFile      string     `json:"displayTargetFile"`
	PackageManager  string     `json:"packageManager"` // npm|pip|gomodules|maven|… — the doc-wide ecosystem
}

type snykVuln struct {
	ID          string   `json:"id"`
	Title       string   `json:"title"`
	Severity    string   `json:"severity"`
	PackageName string   `json:"packageName"`
	Version     string   `json:"version"`
	From        []string `json:"from"`
	Identifiers struct {
		CVE []string `json:"CVE"`
		CWE []string `json:"CWE"`
	} `json:"identifiers"`
}

// FromSnyk parses a Snyk `test --json` document into a types.Scan.
func FromSnyk(data []byte, target string, now time.Time) (types.Scan, error) {
	doc, err := parseSnyk(data)
	if err != nil {
		return types.Scan{}, err
	}
	if target == "" {
		target = firstNonEmpty(doc.ProjectName, doc.TargetFile, "snyk-project")
	}
	scan := newScan("repository", target, now)
	scan.AnchorsFired = []string{"snyk"}
	for i, v := range doc.Vulnerabilities {
		f := types.Finding{
			ID:              fmt.Sprintf("imp-snyk-%04d", i+1),
			RuleID:          "snyk::" + v.ID,
			Tool:            "snyk",
			Severity:        normSeverity(v.Severity),
			Title:           firstNonEmpty(v.Title, v.ID),
			Description:     depDesc(v),
			Endpoint:        pkgRef(v.PackageName, v.Version),
			CWE:             v.Identifiers.CWE,
			DiscoveredAt:    now,
			DiscoveryMethod: &types.DiscoveryMethod{Primary: "imported:snyk"},
		}
		scan.FindingsRaw = append(scan.FindingsRaw, f)
	}
	scan.FindingsEnriched = scan.FindingsRaw
	return scan, nil
}

// SnykToSCA extracts reachability-ready SCA findings (package + CVE + severity) from
// a Snyk document. Symbols are absent in base Snyk JSON, so reachability runs at
// package granularity (any symbol from the package).
func SnykToSCA(data []byte) ([]reachability.SCAFinding, error) {
	doc, err := parseSnyk(data)
	if err != nil {
		return nil, err
	}
	out := make([]reachability.SCAFinding, 0, len(doc.Vulnerabilities))
	for _, v := range doc.Vulnerabilities {
		cve := ""
		if len(v.Identifiers.CVE) > 0 {
			cve = v.Identifiers.CVE[0]
		}
		out = append(out, reachability.SCAFinding{
			ID: v.ID, CVE: cve, Package: v.PackageName, Severity: strings.ToLower(v.Severity),
			Ecosystem: doc.PackageManager, // doc-wide package manager → routes reachability
		})
	}
	return out, nil
}

func parseSnyk(data []byte) (snykDoc, error) {
	var doc snykDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		return doc, fmt.Errorf("snyk: %w", err)
	}
	return doc, nil
}

func depDesc(v snykVuln) string {
	d := ""
	if len(v.Identifiers.CVE) > 0 {
		d = strings.Join(v.Identifiers.CVE, ", ") + ": "
	}
	d += v.Title
	if len(v.From) > 1 {
		d += " (dependency path: " + strings.Join(v.From, " > ") + ")"
	}
	return d
}

func pkgRef(name, version string) string {
	if version == "" {
		return name
	}
	return name + "@" + version
}
