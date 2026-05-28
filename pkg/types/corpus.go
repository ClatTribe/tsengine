package types

import "time"

// Corpus pins the signature / template / database versions used during a
// scan. Captured at scan start; written to vulnerabilities.json and the
// signed manifest. Re-runs by scan_id MUST resolve to the same Corpus to
// satisfy the reproducibility invariant (CLAUDE.md §10).
type Corpus struct {
	// Nuclei is the nuclei templates tag/version (e.g. "v9.8.2").
	Nuclei string `json:"nuclei,omitempty"`

	// SemgrepPacks lists the semgrep rule packs and their versions in
	// "<pack> <version>" form (e.g. "p/owasp-top-10 1.2.0").
	SemgrepPacks []string `json:"semgrep_packs,omitempty"`

	// TrivyDB is the trivy vulnerability database publish timestamp. A
	// pointer so "not resolved" (nil) is distinct from epoch-zero —
	// trivy fetches its DB at scan time, so this is only known once
	// trivy has run.
	TrivyDB *time.Time `json:"trivy_db,omitempty"`

	// KEVSnapshot is the as-of timestamp of the CISA KEV catalog used.
	KEVSnapshot time.Time `json:"kev_snapshot,omitempty"`

	// EPSSSnapshot is the as-of timestamp of the FIRST.org EPSS CSV used.
	EPSSSnapshot time.Time `json:"epss_snapshot,omitempty"`

	// ComplianceCorpus is a versioned identifier of the compliance control
	// mapping corpus, e.g. "soc2-1.4.0+pci-4.0.0+hipaa-2024+cis-v8".
	ComplianceCorpus string `json:"compliance_corpus,omitempty"`

	// Custom captures additional tool-specific corpus versions not
	// enumerated above (e.g. {"checkov":"3.2.0"}).
	Custom map[string]string `json:"custom,omitempty"`
}
