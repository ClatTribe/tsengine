package types

import "time"

// ThreatIntel is the L1.5 threat_intel.enrich annotation. Attached to any
// finding carrying a CVE. See CLAUDE.md §7.
type ThreatIntel struct {
	CVSS       float64    `json:"cvss,omitempty"`
	CVSSVector string     `json:"cvss_vector,omitempty"` // CVSS base vector (AV/AC/PR/UI/S/C/I/A) — attack-vector detail beyond the score
	KEV        *KEVStatus `json:"kev,omitempty"`
	EPSS       *EPSSScore `json:"epss,omitempty"`
	// WeaponRank is Metasploit's own reliability name for the best module targeting this
	// CVE ("excellent" … "manual"). Metasploit's scale, not ours — an operator who knows
	// msfconsole already knows what it means, and a scale we invented on top of their
	// numbers would be one more thing to be wrong about.
	//
	// It rates the MODULE, not your exposure. An excellent-ranked module says the exploit
	// runs reliably where the vulnerability is present; it says nothing about whether this
	// instance is affected.
	WeaponRank string `json:"weapon_rank,omitempty"`
	// SSVC is CISA's own decision assessment (Vulnrichment/ADP), recorded verbatim. Its Automatable
	// point is the only signal here that separates a vulnerability exploited by hand against one
	// target from one that can be driven across an estate — KEV is binary and EPSS is a probability.
	SSVC       *SSVC    `json:"ssvc,omitempty"`
	Advisories []string `json:"advisories,omitempty"`
	Exploits   []string `json:"exploits,omitempty"`
}

// KEVStatus is the CISA Known Exploited Vulnerabilities catalog state for
// a CVE. Listed=true starts compliance SLA clocks; downstream consumers
// rely on this.
// SSVC is CISA's own decision assessment for a CVE, from the Vulnrichment (ADP) programme —
// recorded VERBATIM, never computed.
//
// A full SSVC decision needs the DEFENDER's mission and deployment context, which we do not have;
// inventing it would be a judgement dressed as CISA's. What we carry is the three decision points
// CISA publishes, which are facts about the vulnerability:
//
//	Exploitation     none | poc | active   — CISA's read of exploitation status
//	Automatable      yes | no              — can an attacker automate steps 1-4 of the kill chain
//	TechnicalImpact  partial | total       — what control the attacker gains
//
// Automatable is the one no other feed provides. KEV is binary and covers ~1,700 CVEs, EPSS is a
// probability, and neither separates a vulnerability exploited by hand against one target from one
// that can be driven across an estate.
type SSVC struct {
	Exploitation    string `json:"exploitation,omitempty"`
	Automatable     string `json:"automatable,omitempty"`
	TechnicalImpact string `json:"technical_impact,omitempty"`
}

type KEVStatus struct {
	Listed    bool      `json:"listed"`
	DateAdded time.Time `json:"date_added,omitzero"`
	// Vendor + Product name the affected technology as CISA catalogs it
	// ("Apache", "HTTP Server"). Optional (omitempty) so the dashboard
	// contract and the embedded corpus snapshot stay byte-compatible. They
	// carry the "exploited in the wild in WHICH product" fact, which both
	// informs the reader and drives threat-informed targeting
	// (internal/threatinformed).
	Vendor  string `json:"vendor,omitempty"`
	Product string `json:"product,omitempty"`
	// Advisories are the reference URLs CISA publishes with the entry — the vendor
	// bulletin, the patch, sometimes the directive that mandates its remediation.
	//
	// They were being PARSED AND DISCARDED, which is the third time this exact thing has
	// happened in this one feed (vendorProject/product, then dueDate and ransomware use,
	// now these). Every one of the 1,673 entries carries them, ~3,000 URLs in total, and
	// the architecture doc has claimed "vendor advisory URLs" as a shipped capability the
	// whole time while ThreatIntel.Advisories was never written by any source.
	Advisories []string `json:"advisories,omitempty"`
	// CWEs are the weakness classes CISA publishes for this CVE.
	//
	// They matter far more than a reference list, because CWE is what the compliance
	// crosswalk (§8) is keyed on — and the hook returns early when a finding has none. grype
	// and osv-scanner never set one, so a KEV-listed, ransomware-linked CVE found in a
	// container image was getting NO control mapping at all, while CISA published its CWE in
	// a feed we already fetch. 89% of the catalog carries them.
	CWEs []string `json:"cwes,omitempty"`
	// DueDate is CISA's OWN BOD 22-01 remediation deadline for this CVE. Federal
	// agencies are bound by it; everyone else gets the strongest free statement
	// anywhere of how long a defender is considered to reasonably have. Preferred
	// over a window computed from DateAdded, because a deadline the authority set
	// beats one we derived.
	DueDate time.Time `json:"due_date,omitzero"`
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
