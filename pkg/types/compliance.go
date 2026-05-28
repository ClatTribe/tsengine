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
}
