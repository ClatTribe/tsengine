package supplychain

import (
	"fmt"
	"strings"
	"time"

	"github.com/ClatTribe/tsengine/pkg/types"
)

// Deprecated/abandoned-package detection — the third dependency-set risk class
// (alongside malicious + end-of-life) and the grounded, actionable core of
// "package health": a dependency the maintainer has officially DEPRECATED or
// ABANDONED. It is not malicious and may carry no current CVE, but it receives
// no fixes, so future vulnerabilities go unpatched — the maintenance-debt risk
// Aikido's package-health surfaces. A finding fires only on a corpus match (the
// maintainer's own deprecation), never a heuristic guess; the full numeric
// health score (deps.dev / OpenSSF Scorecard, a live lookup) is a follow-up.

// DeprecatedPackage is a package the maintainer has deprecated/abandoned, with
// its recommended replacement. Versions pins the deprecated cycle(s); empty
// means the whole package is deprecated.
type DeprecatedPackage struct {
	Ecosystem        string   `json:"ecosystem"`
	Name             string   `json:"name"`
	Versions         []string `json:"versions,omitempty"`
	Replacement      string   `json:"replacement"`
	SecurityRelevant bool     `json:"security_relevant"` // unmaintained with security implications → medium, else low
	Note             string   `json:"note,omitempty"`
}

// ScanDeprecated flags any dependency that matches a deprecated/abandoned
// package. Severity is medium when the package is security-relevant
// (unmaintained code on the attack surface) and low otherwise (hygiene).
func ScanDeprecated(pkgs []Package, corpus []DeprecatedPackage, now time.Time) []types.Finding {
	if now.IsZero() {
		now = time.Now()
	}
	now = now.UTC()

	index := map[string][]DeprecatedPackage{}
	for _, d := range corpus {
		index[key(d.Ecosystem, d.Name)] = append(index[key(d.Ecosystem, d.Name)], d)
	}

	var out []types.Finding
	n := 0
	id := func() string { n++; return fmt.Sprintf("dep-%03d", n) }

	for _, p := range pkgs {
		for _, d := range index[key(p.Ecosystem, p.Name)] {
			if !versionAffected(p.Version, d.Versions) {
				continue
			}
			sev := types.SeverityLow
			if d.SecurityRelevant {
				sev = types.SeverityMedium
			}
			rep := ""
			if d.Replacement != "" {
				rep = " Migrate to " + d.Replacement + "."
			}
			out = append(out, types.Finding{
				ID:       id(),
				RuleID:   "deprecated::" + strings.ToLower(p.Name),
				Tool:     "deprecated-packages",
				Severity: sev,
				Title:    "Deprecated dependency: " + p.Name,
				Endpoint: p.Ecosystem + ":" + p.Name + "@" + p.Version,
				Description: fmt.Sprintf("%s (%s) is deprecated / no longer maintained, so future security fixes will not arrive.%s%s",
					p.Name, d.Ecosystem, rep, noteSuffix(d.Note)),
				CWE: []string{"CWE-1104"}, // Use of Unmaintained Third Party Components
				Compliance: &types.Compliance{
					SOC2:    []string{"CC7.1"},
					CISv8:   []string{"2.2"},
					NISTCSF: []string{"ID.RA-01"},
				},
				DiscoveredAt:       now,
				VerificationStatus: types.VerificationVerified, // grounded in the maintainer's deprecation
			})
		}
	}
	return out
}
