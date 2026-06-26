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
