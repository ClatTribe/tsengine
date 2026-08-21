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
	// Vendor + Product name the affected technology as CISA catalogs it
	// ("Apache", "HTTP Server"). Optional (omitempty) so the dashboard
	// contract and the embedded corpus snapshot stay byte-compatible. They
	// carry the "exploited in the wild in WHICH product" fact, which both
	// informs the reader and drives threat-informed targeting
	// (internal/threatinformed).
	Vendor  string `json:"vendor,omitempty"`
	Product string `json:"product,omitempty"`
	// DueDate is CISA's OWN BOD 22-01 remediation deadline for this CVE. Federal
	// agencies are bound by it; everyone else gets the strongest free statement
	// anywhere of how long a defender is considered to reasonably have. Preferred
	// over a window computed from DateAdded, because a deadline the authority set
	// beats one we derived.
	DueDate time.Time `json:"due_date,omitempty"`
	// Ransomware reports CISA's knownRansomwareCampaignUse == "Known". It is a
	// STRICTLY STRONGER claim than Listed: KEV means exploited in the wild,
	// this means exploited by ransomware operators. The two must never be
	// conflated — most of the catalog is Listed and not Ransomware, so treating
	// them alike would either understate the urgent few or overstate the rest.
	Ransomware bool `json:"ransomware,omitempty"`
}

// EPSSScore is the FIRST.org Exploit Prediction Scoring System reading.
// Score is the probability [0,1]; Percentile is rank [0,1].
type EPSSScore struct {
	Score      float64   `json:"score"`
	Percentile float64   `json:"percentile"`
	AsOf       time.Time `json:"as_of"`
}
