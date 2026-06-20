package supplychain

import (
	"fmt"
	"strings"
	"time"

	"github.com/ClatTribe/tsengine/pkg/types"
)

// License-risk detection — the fourth SBOM-derived dependency check, alongside
// malicious / EOL / deprecated. A copyleft dependency in a proprietary or SaaS
// codebase is a legal / IP exposure (it can compel source disclosure), and an
// SCA-platform standard. Grounded in the SBOM's own per-component license
// (syft emits SPDX ids in the CycloneDX licenses[] field) — no guess. Deliberately
// high-signal: only the strong-copyleft families are flagged, so the permissive
// majority (MIT/Apache/BSD/ISC) stays silent.

// ScanLicenses flags dependencies whose license carries copyleft obligations:
// AGPL (network copyleft — the highest SaaS risk) at medium, GPL (strong
// copyleft) at low. Packages with no license in the SBOM, or a permissive
// license, are not flagged (low-noise by design).
func ScanLicenses(pkgs []Package, now time.Time) []types.Finding {
	if now.IsZero() {
		now = time.Now()
	}
	now = now.UTC()

	var out []types.Finding
	n := 0
	id := func() string { n++; return fmt.Sprintf("lic-%03d", n) }

	for _, p := range pkgs {
		class, sev, why := classifyLicense(p.License)
		if class == "" {
			continue
		}
		out = append(out, types.Finding{
			ID:       id(),
			RuleID:   "license::" + class,
			Tool:     "license",
			Severity: sev,
			Title:    fmt.Sprintf("%s-licensed dependency: %s (%s)", strings.ToUpper(class), p.Name, p.License),
			Endpoint: p.Ecosystem + ":" + p.Name + "@" + p.Version,
			Description: fmt.Sprintf("%s is under %s. %s Confirm it is compatible with your distribution model, or replace it with a permissively-licensed alternative.",
				p.Name, p.License, why),
			Compliance: &types.Compliance{
				CISv8:   []string{"2.1"}, // software inventory / asset management
				NISTCSF: []string{"ID.AM-02"},
				SOX:     []string{"ITGC: software asset / license management"},
			},
			DiscoveredAt:       now,
			VerificationStatus: types.VerificationVerified, // grounded in the SBOM's declared license
		})
	}
	return out
}

// classifyLicense returns (class, severity, rationale) for a copyleft license,
// or ("", _, _) for permissive / unknown (not flagged).
func classifyLicense(license string) (string, types.Severity, string) {
	l := strings.ToUpper(strings.TrimSpace(license))
	if l == "" {
		return "", "", ""
	}
	switch {
	case strings.Contains(l, "AGPL"):
		return "agpl", types.SeverityMedium,
			"AGPL is network copyleft: offering the software as a service can compel you to publish your source."
	case strings.Contains(l, "LGPL"):
		// Weak copyleft — linking is generally permitted; do not flag (low-noise).
		return "", "", ""
	case strings.Contains(l, "GPL"):
		return "gpl", types.SeverityLow,
			"GPL is strong copyleft: distributing a derivative work can require releasing your source under the GPL."
	}
	return "", "", ""
}
