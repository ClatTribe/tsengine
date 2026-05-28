package hooks

import "time"

// Corpus version stamps for the embedded L1.5 enrichment data. These
// are recorded into vulnerabilities.json's corpus block so a scan is
// reproducible against the exact mapping/intel snapshot that produced
// it (CLAUDE.md §10). Bump these whenever data/*.json changes.
const (
	// ThreatIntelCorpusVersion identifies the embedded CVE→intel snapshot.
	ThreatIntelCorpusVersion = "ti-snapshot-2026-05-01"

	// ComplianceCorpusVersion identifies the embedded CWE→control map.
	ComplianceCorpusVersion = "soc2-1.0+pci-4.0+hipaa-2024+cis-v8+nist-csf-2.0"
)

// ThreatIntelSnapshot is the as-of date of the embedded KEV/EPSS data.
// Recorded as Corpus.KEVSnapshot / Corpus.EPSSSnapshot.
var ThreatIntelSnapshot = time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
