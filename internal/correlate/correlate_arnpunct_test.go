package correlate

import (
	"strings"
	"testing"
)

// TestChain_ARNAtSentenceEndBridges: an ARN written at the end of a sentence (trailing
// period) in one finding must still bridge to the clean ARN on another surface — the
// correlator trims trailing punctuation so the exact-token match holds (§10 grounding intact).
func TestChain_ARNAtSentenceEndBridges(t *testing.T) {
	arn := "arn:aws:iam::123456789012:role/web-instance-role"
	web := Asset{Type: "web_application", Target: "app.acme.com", Findings: []Finding{{
		ID: "w1", Title: "SSRF", Severity: "high", Verified: true, Endpoint: "https://app.acme.com/f?u=",
		Description: "leaks credentials for " + arn + ".", // trailing period
	}}}
	cloud := Asset{Type: "cloud_account", Target: "123456789012", Findings: []Finding{{
		ID: "c1", Title: "role has administrator access", Severity: "critical", Endpoint: arn,
	}}}
	chains := Correlate([]Asset{web, cloud})
	if len(chains) != 1 {
		t.Fatalf("an ARN at a sentence end must still bridge to one chain, got %d", len(chains))
	}
	var bridged bool
	for _, s := range chains[0].Steps {
		if strings.Contains(s.ViaEntity, arn) {
			bridged = true
		}
	}
	if !bridged {
		t.Errorf("chain must be bridged by the (punctuation-trimmed) ARN: %+v", chains[0].Steps)
	}
}
