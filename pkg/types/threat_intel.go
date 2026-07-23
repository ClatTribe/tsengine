package types

import "time"

// ThreatIntel is the L1.5 threat_intel.enrich annotation. Attached to any
// finding carrying a CVE. See CLAUDE.md §7.
type ThreatIntel struct {
	CVSS       float64    `json:"cvss,omitempty"`
	CVSSVector string     `json:"cvss_vector,omitempty"` // CVSS base vector (AV/AC/PR/UI/S/C/I/A) — attack-vector detail beyond the score
	KEV        *KEVStatus `json:"kev,omitempty"`
	EPSS       *EPSSScore `json:"epss,omitempty"`
	Advisories []string   `json:"advisories,omitempty"`
	Exploits   []string   `json:"exploits,omitempty"`
	// SSVC is the CISA Stakeholder-Specific Vulnerability Categorization decision — the actionable
	// prioritization ("act / attend / track") a mature vuln-management program uses instead of the raw
	// CVSS number, derived deterministically from the exploitation + impact signals above (§7).
	SSVC *SSVC `json:"ssvc,omitempty"`
}

// SSVC is a CISA Stakeholder-Specific Vulnerability Categorization result (the Deployer-tree decision,
// reduced to the exploitation/impact signals we hold). Decision is the action: "act" (remediate now),
// "attend" (out-of-cycle, supervise), or "track" (remediate on the normal schedule). It replaces "is
// CVSS 9.8 scary?" with "what do I DO about it?".
type SSVC struct {
	Decision     string `json:"decision"`           // act | attend | track
	Exploitation string `json:"exploitation"`       // active | poc | none
	Impact       string `json:"impact"`             // high | low
	Automatable  bool   `json:"automatable"`        // the exploit can be automated (AV:N + AC:L, or an exploit exists)
	Rationale    string `json:"rationale"`          // one line explaining the decision
	DueDate      string `json:"due_date,omitempty"` // CISA BOD 22-01 remediation deadline when KEV-listed (YYYY-MM-DD)
}

// KEVStatus is the CISA Known Exploited Vulnerabilities catalog state for
// a CVE. Listed=true starts compliance SLA clocks; downstream consumers
// rely on this.
type KEVStatus struct {
	Listed    bool      `json:"listed"`
	DateAdded time.Time `json:"date_added,omitempty"`
}

// EPSSScore is the FIRST.org Exploit Prediction Scoring System reading.
// Score is the probability [0,1]; Percentile is rank [0,1].
type EPSSScore struct {
	Score      float64   `json:"score"`
	Percentile float64   `json:"percentile"`
	AsOf       time.Time `json:"as_of"`
}
