package correlate

import (
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/pkg/types"
)

// The canonical cross-asset chain: a verified web SQLi leaks an AWS key; the cloud
// scan shows that key's IAM user can escalate to Administrator (a crown jewel). The
// shared AWS key is the grounded bridge.
func TestChain_WebLeakToCloudAdmin(t *testing.T) {
	web := Asset{
		ID: "s-web", Type: "web_application", Target: "https://app.example",
		Findings: []Finding{{
			ID: "web-001", Title: "SQL Injection", Severity: "high", Endpoint: "https://app.example/search?q=",
			Verified: true, Description: "error-based SQLi; dump exposed credentials AKIAIOSFODNN7EXAMPLE",
		}},
	}
	cloud := Asset{
		ID: "s-cloud", Type: "cloud_account", Target: "aws-acct-1",
		Findings: []Finding{{
			ID: "cl-009", Title: "IAM user can escalate to Administrator", Severity: "critical",
			Description: "principal for access key AKIAIOSFODNN7EXAMPLE has iam:PutUserPolicy → privilege escalation",
		}},
	}
	chains := Correlate([]Asset{web, cloud})
	if len(chains) != 1 {
		t.Fatalf("want 1 cross-asset chain, got %d: %+v", len(chains), chains)
	}
	c := chains[0]
	if len(c.Steps) != 2 {
		t.Fatalf("want 2 steps, got %d", len(c.Steps))
	}
	if c.Steps[0].AssetType != "web_application" || !c.Steps[0].Verified {
		t.Errorf("step 1 should be the verified web entry: %+v", c.Steps[0])
	}
	if !strings.Contains(c.Steps[0].ViaEntity, "AKIAIOSFODNN7EXAMPLE") {
		t.Errorf("bridge should cite the leaked AWS key: %q", c.Steps[0].ViaEntity)
	}
	if c.Steps[1].AssetType != "cloud_account" || !c.Steps[1].CrownJewel {
		t.Errorf("step 2 should be the cloud crown jewel: %+v", c.Steps[1])
	}
	t.Log("\n" + Render(chains))
}

// No shared identifier → no chain. The web finding and cloud crown jewel are real
// but UNRELATED (different keys); correlation must not invent a link.
func TestNoChain_WhenNoSharedIdentifier(t *testing.T) {
	web := Asset{Type: "web_application", Target: "https://app.example", Findings: []Finding{
		{ID: "w1", Title: "SQLi", Severity: "high", Verified: true, Description: "leaks AKIAAAAAAAAAAAAAAAA1"},
	}}
	cloud := Asset{Type: "cloud_account", Target: "acct", Findings: []Finding{
		{ID: "c1", Title: "admin privilege escalation", Severity: "critical", Description: "key AKIABBBBBBBBBBBBBBBB2 escalates"},
	}}
	if chains := Correlate([]Asset{web, cloud}); len(chains) != 0 {
		t.Fatalf("unrelated findings must NOT correlate (no shared identifier): %+v", chains)
	}
}

// Host bridge: a verified web exploit on host H + an ip_address asset for H with a
// finding that bridges (shared key) to a cloud crown jewel.
func TestChain_HostThenCredentialBridge(t *testing.T) {
	web := Asset{Type: "web_application", Target: "https://shop.example", Findings: []Finding{
		{ID: "w1", Title: "RCE", Severity: "critical", Verified: true, Endpoint: "https://shop.example/upload",
			Description: "remote code execution; reads instance creds ASIAZZZZZZZZZZZZZZZZ"},
	}}
	cloud := Asset{Type: "cloud_account", Target: "acct", Findings: []Finding{
		{ID: "c1", Title: "role grants administrator access", Severity: "critical",
			Description: "session ASIAZZZZZZZZZZZZZZZZ assumes admin role"},
	}}
	chains := Correlate([]Asset{web, cloud})
	if len(chains) != 1 || !chains[0].Steps[len(chains[0].Steps)-1].CrownJewel {
		t.Fatalf("expected a chain ending at the crown jewel: %+v", chains)
	}
}

// FromScan adapts the L1 dashboard finding (incl. raw output for secret extraction).
func TestFromScan(t *testing.T) {
	scan := types.Scan{
		ScanID: "s1", Asset: types.Asset{Type: "repository", Target: "github.com/acme/app"},
		FindingsEnriched: []types.Finding{{
			ID: "f1", RuleID: "gitleaks::aws", Tool: "gitleaks", Severity: types.SeverityHigh,
			Title: "AWS key committed", RawOutput: []byte(`{"secret":"AKIAIOSFODNN7EXAMPLE"}`),
		}},
	}
	a := FromScan(scan)
	if a.Type != "repository" || len(a.Findings) != 1 {
		t.Fatalf("FromScan wrong: %+v", a)
	}
	ents := extractEntities(a.Findings[0])
	found := false
	for _, e := range ents {
		if e.Kind == EntAWSKey && e.Value == "AKIAIOSFODNN7EXAMPLE" {
			found = true
		}
	}
	if !found {
		t.Errorf("AWS key not extracted from raw output: %+v", ents)
	}
}
