// Package supplychain assesses dependency-set risk that the SCA tools (CVE
// scanners) do not: MALICIOUS packages (this file — typosquatted, backdoored,
// or hijacked, hostile by design and usually no CVE) and END-OF-LIFE runtimes /
// frameworks (eol.go — past their published support date, unpatched and growing).
// Both are grounded in authoritative corpora (OSSF malicious-packages / OSV MAL-
// and endoflife.date), matched against the dependency set the SBOM (syft)
// produces — never a heuristic guess; a clean dependency set yields zero.
//
// --- malicious packages ---
// A malicious package is a distinct threat from a *vulnerable* dependency (a CVE
// in legitimate code, which the SCA tools trivy/grype/osv-scanner cover):
// hostile by design (credential stealers, crypto-miners, protestware), often
// carries no CVE, and is the supply-chain attack vector behind incidents like
// ua-parser-js (2021), node-ipc (2022), and the ctx / typosquat PyPI campaigns.
//
// Grounded, not heuristic: a finding is raised only when a dependency MATCHES an
// entry in the known-malicious corpus, which is sourced from authoritative OSS
// advisories — the OSSF malicious-packages dataset + OSV `MAL-` records (free,
// no API key) — the same corpus discipline as threat_intel (KEV/EPSS). The
// embedded DefaultCorpus is a checked-in snapshot of well-documented incidents;
// `corpus refresh` ingests the full OSSF feed out of band and pins the version
// per scan (so it's feed-fresh yet reproducible for the evidence pack, §10).
//
// LLM-free + deterministic: a clean dependency set yields ZERO findings.
package supplychain

import (
	"fmt"
	"strings"
	"time"

	"github.com/ClatTribe/tsengine/pkg/types"
)

// MaliciousPackage is one known-malicious package, grounded in a public
// advisory. Versions lists the affected versions; empty means every version of
// the package is malicious (e.g. a pure typosquat that should never be installed).
type MaliciousPackage struct {
	Ecosystem string   `json:"ecosystem"` // npm | pypi | go | rubygems | ...
	Name      string   `json:"name"`
	Versions  []string `json:"versions,omitempty"`
	Advisory  string   `json:"advisory"` // provenance (e.g. "OSV MAL-…", "ua-parser-js 2021")
	Summary   string   `json:"summary"`
}

// Package is one resolved dependency from the project's lockfile / SBOM
// (produced by syft / the SCA tools).
type Package struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
	Version   string `json:"version"`
	License   string `json:"license,omitempty"` // SPDX id/expression from the SBOM (optional; used by ScanLicenses)
}

// Options tunes the scan.
type Options struct {
	Now time.Time
}

// Scan flags every dependency that matches a known-malicious package. Match is
// case-insensitive on (ecosystem, name); when the corpus entry pins versions,
// the dependency's version must match too — otherwise every version is hostile.
func Scan(pkgs []Package, corpus []MaliciousPackage, opts Options) []types.Finding {
	now := opts.Now
	if now.IsZero() {
		now = time.Now()
	}
	now = now.UTC()

	// Index the corpus by (ecosystem, name) for O(1) lookup.
	index := map[string][]MaliciousPackage{}
	for _, m := range corpus {
		index[key(m.Ecosystem, m.Name)] = append(index[key(m.Ecosystem, m.Name)], m)
	}

	var out []types.Finding
	n := 0
	id := func() string { n++; return fmt.Sprintf("mal-%03d", n) }

	for _, p := range pkgs {
		for _, m := range index[key(p.Ecosystem, p.Name)] {
			if !versionAffected(p.Version, m.Versions) {
				continue
			}
			coord := p.Ecosystem + ":" + p.Name + "@" + p.Version
			out = append(out, types.Finding{
				ID:       id(),
				RuleID:   "malicious-packages::" + slug(m.Advisory),
				Tool:     "malicious-packages",
				Severity: types.SeverityCritical, // a hostile dependency is RCE-in-your-build
				Title:    "Malicious dependency: " + p.Name + "@" + p.Version,
				Endpoint: coord,
				Description: fmt.Sprintf("%s (%s). %s Remove it immediately, rotate any secrets it could have read, and pin a known-good version.",
					p.Name, m.Ecosystem, m.Summary),
				CWE:             []string{"CWE-506"}, // Embedded Malicious Code
				MITRETechniques: []string{"T1195.001"},
				Compliance: &types.Compliance{
					SOC2:      []string{"CC6.1", "CC7.1"},
					CISv8:     []string{"16.4", "16.6"},
					NIST80053: []string{"SR-3", "SR-11", "SI-7"},
					NISTCSF:   []string{"PR.DS-06", "DE.CM-08"},
				},
				DiscoveredAt: now,
				// grounded by an authoritative advisory match, not a re-fired exploit:
				VerificationStatus: types.VerificationVerified,
			})
		}
	}
	return out
}

func key(eco, name string) string {
	return strings.ToLower(eco) + "\x00" + strings.ToLower(name)
}

// versionAffected reports whether v is in the affected set. An empty set means
// every version is malicious (typosquats / wholly-malicious packages).
func versionAffected(v string, affected []string) bool {
	if len(affected) == 0 {
		return true
	}
	for _, a := range affected {
		if strings.EqualFold(strings.TrimSpace(v), strings.TrimSpace(a)) {
			return true
		}
	}
	return false
}

func slug(s string) string {
	s = strings.ToLower(s)
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == ' ' || r == '-' || r == '_' || r == '/' || r == ':':
			b.WriteRune('-')
		}
	}
	out := strings.Trim(b.String(), "-")
	if out == "" {
		return "malicious"
	}
	return out
}
