package types

// Compliance is the L1.5 compliance.map annotation — the set of
// compliance-framework controls a finding maps to. See CLAUDE.md §8.
//
// Mapping is annotation, not gate: L1 emits the technical finding
// regardless; this just records which controls it affects.
type Compliance struct {
	SOC2     []string `json:"soc2,omitempty"`
	PCI      []string `json:"pci,omitempty"`
	HIPAA    []string `json:"hipaa,omitempty"`
	CISv8    []string `json:"cis_v8,omitempty"`
	NISTCSF  []string `json:"nist_csf,omitempty"`
	ISO27001 []string `json:"iso27001,omitempty"`
	// Privacy + sector + government frameworks (CLAUDE.md §8 day-1 set, expanded for
	// competitor-parity coverage). Each is annotation-only, same as the originals.
	GDPR       []string `json:"gdpr,omitempty"`         // EU GDPR (Article refs, mostly Art. 32 security-of-processing)
	ISO27701   []string `json:"iso27701,omitempty"`     // ISO/IEC 27701:2019 privacy-information-management clauses
	NIST80053  []string `json:"nist_800_53,omitempty"`  // NIST SP 800-53 r5 control IDs
	NIST800171 []string `json:"nist_800_171,omitempty"` // NIST SP 800-171 r2 CUI requirements
	CCPA       []string `json:"ccpa,omitempty"`         // California CCPA/CPRA (Civil Code §1798.x)
	SOX        []string `json:"sox,omitempty"`          // Sarbanes-Oxley IT general controls (ITGC domains)
	FedRAMP    []string `json:"fedramp,omitempty"`      // FedRAMP Moderate baseline (800-53-derived control IDs)
	DPDP       []string `json:"dpdp,omitempty"`         // India Digital Personal Data Protection Act 2023 (Section refs)
}
