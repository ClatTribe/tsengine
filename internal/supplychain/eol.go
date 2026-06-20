package supplychain

import (
	"fmt"
	"strings"
	"time"

	"github.com/ClatTribe/tsengine/pkg/types"
)

// EOL (end-of-life) detection — the second supply-chain risk class alongside
// malicious packages: a runtime or framework that has reached end-of-life gets
// no security patches, so its CVE exposure only grows. Grounded in the public
// endoflife.date dataset (free, no API key) — the embedded DefaultEOLCorpus is
// a checked-in snapshot of widely-used products; `corpus refresh` ingests the
// full feed. A finding is raised only when a dependency's version cycle is past
// (or near) its published EOL date — never a guess.

// EOLEntry is one product version-cycle and its end-of-life date.
type EOLEntry struct {
	Name    string `json:"name"`     // django | nodejs | python | php | ruby | rails | dotnet | spring-boot
	Cycle   string `json:"cycle"`    // version-cycle prefix: "2.7", "3.2", "12"
	EOLDate string `json:"eol_date"` // RFC3339 date (YYYY-MM-DD)
	Note    string `json:"note,omitempty"`
}

// nameAliases maps SBOM package names to the corpus product name.
var nameAliases = map[string]string{
	"node": "nodejs", "node.js": "nodejs",
	"python3": "python", "cpython": "python",
	"ruby-on-rails": "rails",
	".net":          "dotnet", "dotnet-runtime": "dotnet",
}

// ScanEOL flags any dependency whose version cycle is at/after its EOL date
// (high), or within the heads-up window before it (medium). now is the
// assessment date (the EOL fact + now are what make it grounded + reproducible).
func ScanEOL(pkgs []Package, corpus []EOLEntry, now time.Time) []types.Finding {
	if now.IsZero() {
		now = time.Now()
	}
	now = now.UTC()
	const headsUpDays = 180

	// Index by product name → its cycles.
	byName := map[string][]EOLEntry{}
	for _, e := range corpus {
		byName[strings.ToLower(e.Name)] = append(byName[strings.ToLower(e.Name)], e)
	}

	var out []types.Finding
	n := 0
	id := func() string { n++; return fmt.Sprintf("eol-%03d", n) }
	seen := map[string]bool{}

	for _, p := range pkgs {
		name := strings.ToLower(strings.TrimSpace(p.Name))
		if alias, ok := nameAliases[name]; ok {
			name = alias
		}
		for _, e := range byName[name] {
			if !cycleMatches(p.Version, e.Cycle) {
				continue
			}
			eol, err := time.Parse("2006-01-02", e.EOLDate)
			if err != nil {
				continue
			}
			eol = eol.UTC()
			dedup := name + "\x00" + e.Cycle
			if seen[dedup] {
				continue
			}

			var sev types.Severity
			var verb string
			switch {
			case !now.Before(eol): // now >= eol → past end-of-life
				sev, verb = types.SeverityHigh, "reached end-of-life on"
			case now.AddDate(0, 0, headsUpDays).After(eol): // EOL within the heads-up window
				sev, verb = types.SeverityMedium, "reaches end-of-life on"
			default:
				continue // still well-supported
			}
			seen[dedup] = true
			out = append(out, types.Finding{
				ID:       id(),
				RuleID:   "eol::" + name + "-" + e.Cycle,
				Tool:     "eol",
				Severity: sev,
				Title:    fmt.Sprintf("End-of-life %s %s", titleName(e.Name), e.Cycle),
				Endpoint: p.Ecosystem + ":" + p.Name + "@" + p.Version,
				Description: fmt.Sprintf("%s %s %s %s and no longer receives security patches; its vulnerability exposure grows over time. Upgrade to a supported release.%s",
					titleName(e.Name), e.Cycle, verb, e.EOLDate, noteSuffix(e.Note)),
				CWE: []string{"CWE-1104"}, // Use of Unmaintained Third Party Components
				Compliance: &types.Compliance{
					SOC2:      []string{"CC7.1"},
					PCI:       []string{"6.3.3"},
					CISv8:     []string{"2.2", "7.3"},
					NIST80053: []string{"SA-22", "SI-2"},
					NISTCSF:   []string{"ID.RA-01", "PR.IP-12"},
				},
				DiscoveredAt:       now,
				VerificationStatus: types.VerificationVerified, // grounded in the published EOL date
			})
		}
	}
	return out
}

// cycleMatches reports whether version v belongs to the cycle (v == cycle, or v
// starts with "cycle."). "2.7.18" matches "2.7"; "2.70.0" does NOT.
func cycleMatches(v, cycle string) bool {
	v = strings.TrimSpace(v)
	if v == cycle {
		return true
	}
	return strings.HasPrefix(v, cycle+".")
}

func titleName(s string) string {
	switch s {
	case "nodejs":
		return "Node.js"
	case "php":
		return "PHP"
	case "dotnet":
		return ".NET"
	}
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

func noteSuffix(note string) string {
	if note == "" {
		return ""
	}
	return " " + note
}
