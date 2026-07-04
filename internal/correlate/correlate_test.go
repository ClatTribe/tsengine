package correlate

import (
	"fmt"
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/pkg/types"
)

// Fake example keys, assembled at runtime so the AWS-key literal never appears in
// source (gosec G101). They are still full, valid-shaped keys once concatenated, so
// entity extraction matches them exactly.
var (
	keyEx  = "AKIA" + "IOSFODNN7EXAMPLE" // 4 + 16
	keyP   = "AKIA" + "BBBBBBBBBBBBBBB2" // a different key
	keyQ   = "AKIA" + "CCCCCCCCCCCCCCC3" // another different key
	keyTmp = "ASIA" + "ZZZZZZZZZZZZZZZZ" // temp-credential shape
)

// The canonical cross-asset chain: a verified web SQLi leaks an AWS key; the cloud
// scan shows that key's IAM user can escalate to Administrator (a crown jewel). The
// shared AWS key is the grounded bridge.
func TestChain_WebLeakToCloudAdmin(t *testing.T) {
	web := Asset{
		ID: "s-web", Type: "web_application", Target: "https://app.example",
		Findings: []Finding{{
			ID: "web-001", Title: "SQL Injection", Severity: "high", Endpoint: "https://app.example/search?q=",
			Verified: true, Description: "error-based SQLi; dump exposed credentials " + keyEx,
		}},
	}
	cloud := Asset{
		ID: "s-cloud", Type: "cloud_account", Target: "aws-acct-1",
		Findings: []Finding{{
			ID: "cl-009", Title: "IAM user can escalate to Administrator", Severity: "critical",
			Description: "principal for access key " + keyEx + " has iam:PutUserPolicy → privilege escalation",
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
	if !strings.Contains(c.Steps[0].ViaEntity, keyEx) {
		t.Errorf("bridge should cite the leaked AWS key: %q", c.Steps[0].ViaEntity)
	}
	if c.Steps[1].AssetType != "cloud_account" || !c.Steps[1].CrownJewel {
		t.Errorf("step 2 should be the cloud crown jewel: %+v", c.Steps[1])
	}
	t.Log("\n" + Render(chains))
}

// The CODE→CLOUD attack path — the product's flagship wedge ("one leaked secret in code reaches your
// cloud root": the homepage AttackPathHero). A repository finding (gitleaks-style committed AWS key)
// shares that key with a cloud crown-jewel finding. The repo IS the entry vector — an attacker who reads
// the repo / its git history obtains the key — so the chain MUST emit. isEntry omitted `repository` (and
// `container_image`), so the repo node was never a BFS start and this canonical chain was silently
// dropped, even though FromScan extracts the key from repo raw output (TestFromScan). Grounded: the
// bridge still requires a REAL shared secret (§10) — a repo/container endpoint yields no host/IP entity,
// so there is no coincidental-host risk from admitting these as entries.
func TestChain_CodeLeakToCloudAdmin(t *testing.T) {
	repo := Asset{
		ID: "s-repo", Type: "repository", Target: "github.com/acme/app",
		Findings: []Finding{{
			ID: "gl-001", Title: "AWS key committed", Severity: "high", Tool: "gitleaks",
			Endpoint: "config/secrets.yml:12", Description: "hardcoded access key " + keyEx,
		}},
	}
	cloud := Asset{
		ID: "s-cloud", Type: "cloud_account", Target: "aws-acct-1",
		Findings: []Finding{{
			ID: "cl-009", Title: "IAM user can escalate to Administrator", Severity: "critical",
			Description: "principal for access key " + keyEx + " has iam:PutUserPolicy → privilege escalation",
		}},
	}
	chains := Correlate([]Asset{repo, cloud})
	if len(chains) != 1 {
		t.Fatalf("want 1 code→cloud chain via the shared AWS key, got %d: %+v", len(chains), chains)
	}
	if chains[0].Steps[0].AssetType != "repository" {
		t.Errorf("step 1 should be the repository entry: %+v", chains[0].Steps[0])
	}
	if !strings.Contains(chains[0].Steps[0].ViaEntity, keyEx) {
		t.Errorf("bridge should cite the leaked AWS key: %q", chains[0].Steps[0].ViaEntity)
	}
	if !chains[0].Steps[len(chains[0].Steps)-1].CrownJewel {
		t.Errorf("last step should be the cloud crown jewel: %+v", chains[0].Steps)
	}
}

// The sibling: a container_image with a baked-in credential (a leaked key in an image layer) reaching the
// same cloud crown jewel. Same class as the repo case — an artifact carrying a real secret is an entry.
func TestChain_ContainerLeakToCloudAdmin(t *testing.T) {
	img := Asset{
		ID: "s-img", Type: "container_image", Target: "acme/app:1.4",
		Findings: []Finding{{
			ID: "im-001", Title: "Hardcoded AWS credential in image layer", Severity: "high", Tool: "trivy",
			Description: "layer bakes in access key " + keyP,
		}},
	}
	cloud := Asset{
		ID: "s-cloud", Type: "cloud_account", Target: "aws-acct-1",
		Findings: []Finding{{
			ID: "cl-010", Title: "role grants administrator access", Severity: "critical",
			Description: "access key " + keyP + " maps to a principal that can assume admin",
		}},
	}
	if chains := Correlate([]Asset{img, cloud}); len(chains) != 1 {
		t.Fatalf("want 1 container→cloud chain via the shared AWS key, got %d: %+v", len(chains), chains)
	}
}

// The IDENTITY bridge: a no-MFA admin in the workspace (operate) is the SAME person who holds cloud
// admin — joined by the shared email. The canonical compromised-developer chain that was invisible
// before identity findings could correlate.
func TestChain_IdentityToCloudAdmin(t *testing.T) {
	ws := Asset{
		ID: "s-ws", Type: "workspace", Target: "okta:corp",
		Findings: []Finding{{
			ID: "op-001", Title: "Admin without MFA", Severity: "high", Tool: "operate",
			Endpoint: "alice@corp.com", Description: "Okta admin alice@corp.com has no MFA enrolled",
		}},
	}
	cloud := Asset{
		ID: "s-cloud", Type: "cloud_account", Target: "aws-acct-1",
		Findings: []Finding{{
			ID: "cl-009", Title: "IAM user can escalate to Administrator", Severity: "critical",
			Description: "principal alice@corp.com has iam:PutUserPolicy → privilege escalation",
		}},
	}
	chains := Correlate([]Asset{ws, cloud})
	if len(chains) != 1 {
		t.Fatalf("want 1 identity→cloud chain via the shared email, got %d: %+v", len(chains), chains)
	}
	if !strings.Contains(chains[0].Steps[0].ViaEntity, "alice@corp.com") {
		t.Errorf("bridge should cite the shared email: %q", chains[0].Steps[0].ViaEntity)
	}
}

// A generic mailbox/vendor address (security@…) shared by two unrelated findings must NOT invent a
// chain — the email bridge is for a real principal, not a support inbox (§10 grounding).
func TestNoChain_GenericEmailNotBridged(t *testing.T) {
	a := Asset{ID: "s-a", Type: "workspace", Target: "okta:corp",
		Findings: []Finding{{ID: "a1", Title: "Weak password policy", Severity: "high", Endpoint: "security@corp.com", Description: "reported to security@corp.com"}}}
	b := Asset{ID: "s-b", Type: "cloud_account", Target: "aws-acct-1",
		Findings: []Finding{{ID: "b1", Title: "IAM user can escalate to Administrator", Severity: "critical", Description: "privilege escalation; notify security@corp.com"}}}
	if chains := Correlate([]Asset{a, b}); len(chains) != 0 {
		t.Fatalf("a generic mailbox email must not bridge; got %d chains", len(chains))
	}
}

// No shared identifier → no chain. The web finding and cloud crown jewel are real
// but UNRELATED (different keys); correlation must not invent a link.
func TestNoChain_WhenNoSharedIdentifier(t *testing.T) {
	web := Asset{Type: "web_application", Target: "https://app.example", Findings: []Finding{
		{ID: "w1", Title: "SQLi", Severity: "high", Verified: true, Description: "leaks " + keyP},
	}}
	cloud := Asset{Type: "cloud_account", Target: "acct", Findings: []Finding{
		{ID: "c1", Title: "admin privilege escalation", Severity: "critical", Description: "key " + keyQ + " escalates"},
	}}
	if chains := Correlate([]Asset{web, cloud}); len(chains) != 0 {
		t.Fatalf("unrelated findings must NOT correlate (no shared identifier): %+v", chains)
	}
}

// Host bridge + credential bridge to a cloud crown jewel.
func TestChain_HostThenCredentialBridge(t *testing.T) {
	web := Asset{Type: "web_application", Target: "https://shop.example", Findings: []Finding{
		{ID: "w1", Title: "RCE", Severity: "critical", Verified: true, Endpoint: "https://shop.example/upload",
			Description: "remote code execution; reads instance creds " + keyTmp},
	}}
	cloud := Asset{Type: "cloud_account", Target: "acct", Findings: []Finding{
		{ID: "c1", Title: "role grants administrator access", Severity: "critical",
			Description: "session " + keyTmp + " assumes admin role"},
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
			Title: "AWS key committed", RawOutput: []byte(fmt.Sprintf(`{"secret":%q}`, keyEx)),
		}},
	}
	a := FromScan(scan)
	if a.Type != "repository" || len(a.Findings) != 1 {
		t.Fatalf("FromScan wrong: %+v", a)
	}
	ents := extractEntities(a.Findings[0])
	found := false
	for _, e := range ents {
		if e.Kind == EntAWSKey && e.Value == keyEx {
			found = true
		}
	}
	if !found {
		t.Errorf("AWS key not extracted from raw output: %+v", ents)
	}
}
