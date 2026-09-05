package hooks

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

// TestComplianceCorpusVersionPinsTheData is the guard ADR 0031 D2b requires: the corpus version
// string is DATA, and a pinned corpus whose version never moves makes two different crosswalks
// indistinguishable inside an evidence block — defeating the pin. So when the embedded
// compliance.json changes WITHOUT ComplianceCorpusVersion being bumped, this test fails and names
// the fix.
//
// On a legitimate corpus edit: update the expected prefix below AND bump ComplianceCorpusVersion
// (version.go) in the same PR. The version string should describe the corpus; this hash proves it
// describes THIS corpus.
func TestComplianceCorpusVersionPinsTheData(t *testing.T) {
	sum := sha256.Sum256(complianceCorpus)
	got := hex.EncodeToString(sum[:])
	const recorded = "0c5d8c06f68e9076" // first 16 bytes of data/compliance.json @ soc2-1.0+pci-4.0+hipaa-2024+cis-v8+nist-csf-2.0+dora-2022-2554+uk-ce
	if !strings.HasPrefix(got, recorded) {
		t.Fatalf("embedded compliance.json changed (sha256 now %s…) but ComplianceCorpusVersion was "+
			"not bumped — two different corpora would be indistinguishable in a pinned evidence pack.\n"+
			"Fix: bump ComplianceCorpusVersion in version.go AND update `recorded` here, in the same change.",
			got[:16])
	}
}
