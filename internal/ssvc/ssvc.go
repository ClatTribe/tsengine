// Package ssvc computes a CISA SSVC (Stakeholder-Specific Vulnerability Categorization) decision — the
// actionable "act / attend / track" prioritization a mature vuln-management program uses instead of the
// raw CVSS number. It answers "what do I DO about this?" from the exploitation + impact signals the
// threat-intel enrichment already holds (KEV, public-exploit refs, EPSS, CVSS), so a security engineer
// isn't left triaging a wall of "9.8 critical" CVEs by hand.
//
// This is the CISA SSVC Deployer tree, reduced to the decision points we can ground from the pinned
// corpus (§10 — never invented): Exploitation (none/poc/active), Automatable, and technical Impact.
// Deterministic + pure + tested. The full tree also weighs Exposure + Mission/Safety impact, which need
// per-asset context the enrichment hook lacks; those are the documented next inputs.
package ssvc

import (
	"fmt"
	"strings"
	"time"

	"github.com/ClatTribe/tsengine/pkg/types"
)

// Input is the grounded signal set (all from the threat-intel corpus / the finding severity).
type Input struct {
	KEVListed     bool // CISA KEV → actively exploited in the wild
	KEVDateAdded  time.Time
	ExploitExists bool    // an ExploitDB/Metasploit ref exists → a public/weaponized exploit
	EPSS          float64 // FIRST.org exploitation probability [0,1]
	CVSS          float64 // base score
	HighSeverity  bool    // the finding is rated high/critical
	CVSSVector    string  // AV/AC/... — used to judge Automatable
}

// bod2201Window is the default CISA BOD 22-01 remediation window for a KEV CVE (the catalog's own due
// dates are typically ~3 weeks from listing; we don't carry the exact per-CVE dueDate, so this is the
// documented default when KEV-listed).
const bod2201Window = 21 * 24 * time.Hour

// Decide returns the SSVC decision for a CVE-bearing finding, or nil when there's no CVE signal to reason
// over (no KEV / exploit / EPSS / CVSS) — no signal, no decision (§10).
func Decide(in Input) *types.SSVC {
	if !in.KEVListed && !in.ExploitExists && in.EPSS == 0 && in.CVSS == 0 && !in.HighSeverity {
		return nil
	}
	exploitation := exploitationOf(in)
	impact := "low"
	if in.HighSeverity || in.CVSS >= 7.0 {
		impact = "high"
	}
	automatable := isAutomatable(in)

	decision, rationale := decide(exploitation, impact, automatable)
	out := &types.SSVC{
		Decision:     decision,
		Exploitation: exploitation,
		Impact:       impact,
		Automatable:  automatable,
		Rationale:    rationale,
	}
	if in.KEVListed && !in.KEVDateAdded.IsZero() {
		out.DueDate = in.KEVDateAdded.Add(bod2201Window).UTC().Format("2006-01-02")
	}
	return out
}

// exploitationOf: active (KEV) > poc (a public exploit exists, or a high EPSS says weaponization is
// likely) > none.
func exploitationOf(in Input) string {
	switch {
	case in.KEVListed:
		return "active"
	case in.ExploitExists || in.EPSS >= 0.5:
		return "poc"
	default:
		return "none"
	}
}

// isAutomatable: the exploit can be driven at scale — a network-reachable, low-complexity vector
// (AV:N + AC:L) OR a ready-made exploit exists (Metasploit/ExploitDB automate steps 1–4 of the chain).
func isAutomatable(in Input) bool {
	v := strings.ToUpper(in.CVSSVector)
	if strings.Contains(v, "AV:N") && strings.Contains(v, "AC:L") {
		return true
	}
	return in.ExploitExists
}

// decide is the reduced SSVC Deployer tree.
func decide(exploitation, impact string, automatable bool) (decision, rationale string) {
	switch exploitation {
	case "active":
		if impact == "high" {
			return "act", "actively exploited in the wild (CISA KEV) with high technical impact — remediate now"
		}
		return "attend", "actively exploited in the wild (CISA KEV) but lower impact — remediate out-of-cycle, supervised"
	case "poc":
		if impact == "high" && automatable {
			return "attend", "a public/automatable exploit exists and impact is high — remediate out-of-cycle"
		}
		if impact == "high" {
			return "attend", "a public exploit exists and impact is high — remediate out-of-cycle"
		}
		return "track", "a public exploit exists but impact is low — remediate on the normal schedule"
	default: // none
		if impact == "high" {
			return "track", "no known exploitation yet, but high impact — remediate on the normal schedule and monitor for exploitation"
		}
		return "track", "no known exploitation and low impact — remediate on the normal schedule"
	}
}

// FromThreatIntel is the convenience adapter: build the Input from an attached ThreatIntel + the finding
// severity and Decide. Returns nil when ti is nil.
func FromThreatIntel(ti *types.ThreatIntel, highSeverity bool) *types.SSVC {
	if ti == nil {
		return nil
	}
	in := Input{
		ExploitExists: len(ti.Exploits) > 0,
		CVSS:          ti.CVSS,
		CVSSVector:    ti.CVSSVector,
		HighSeverity:  highSeverity,
	}
	if ti.KEV != nil {
		in.KEVListed = ti.KEV.Listed
		in.KEVDateAdded = ti.KEV.DateAdded
	}
	if ti.EPSS != nil {
		in.EPSS = ti.EPSS.Score
	}
	return Decide(in)
}

// String renders the decision compactly for a digest line.
func String(s *types.SSVC) string {
	if s == nil {
		return ""
	}
	due := ""
	if s.DueDate != "" {
		due = fmt.Sprintf(" (due %s)", s.DueDate)
	}
	return fmt.Sprintf("SSVC:%s%s [%s/%s]", s.Decision, due, s.Exploitation, s.Impact)
}
