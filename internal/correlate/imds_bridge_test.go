package correlate

import (
	"strings"
	"testing"
)

// TestIMDSRoleBridgesSSRFToCloudPrivesc reproduces the chain AWSGoat (INE) documents and this
// engine could not follow: module-1 runs XSS -> SQLi -> IDOR -> SSRF -> IMDS -> stolen instance
// credentials -> IAM privilege escalation. Every step was detected; NONE of them bridged, so the
// web SSRF and the cloud privesc were reported as two unrelated findings — missing the hop that is
// the actual attack.
//
// Nothing else can join them: IMDS credentials never appear as an AKIA string, and the web finding
// carries no ARN. The shared identifier is the ROLE NAME, on both sides.
func TestIMDSRoleBridgesSSRFToCloudPrivesc(t *testing.T) {
	ssrf := Finding{
		Title:       "SSRF reaches instance metadata service",
		Description: "the endpoint fetched http://169.254.169.254/latest/meta-data/iam/security-credentials/blog-role and returned the credentials",
		Endpoint:    "https://app.example.com/fetch?url=",
	}
	privesc := Finding{
		Title:       "IAM role can escalate to admin",
		Description: "arn:aws:iam::123456789012:role/blog-role has iam:AttachRolePolicy and can attach AdministratorAccess",
	}

	se, pe := extractEntities(ssrf), extractEntities(privesc)
	shared := map[string]bool{}
	for _, a := range se {
		for _, b := range pe {
			if a.Kind == b.Kind && a.Value == b.Value {
				shared[string(a.Kind)+":"+a.Value] = true
			}
		}
	}
	if len(shared) == 0 {
		t.Fatalf("the SSRF->IMDS finding and the cloud privesc on the SAME ROLE share no entity, so they\n"+
			"cannot chain — this is the AWSGoat gap.\n  ssrf entities:   %v\n  privesc entities: %v", se, pe)
	}
	if !shared["iam_role:blog-role"] {
		t.Errorf("expected the bridge to be the shared ROLE NAME, got %v", shared)
	}
}

// TestIMDSBridgeDoesNotInventChains is the over-bridging guard, and it matters more than the bridge.
// EntIAMRole joins on a NAME, not a full ARN (the IMDS path carries no account id) — so a ubiquitous
// name like "admin" would link findings from unrelated accounts that merely share a naming
// convention. A fabricated cross-surface chain is worse than a missing one: it sends someone to
// revoke access on a principal that was never compromised.
func TestIMDSBridgeDoesNotInventChains(t *testing.T) {
	a := Finding{Description: "SSRF read http://169.254.169.254/latest/meta-data/iam/security-credentials/admin"}
	b := Finding{Description: "arn:aws:iam::999988887777:role/admin can escalate"}
	for _, e := range append(extractEntities(a), extractEntities(b)...) {
		if e.Kind == EntIAMRole && strings.EqualFold(e.Value, "admin") {
			t.Error("a generic role name ('admin') was extracted as a bridge entity — two unrelated accounts\n" +
				"following the same naming convention would be chained into a fabricated attack path")
		}
	}
}

// TestIMDSBridgeNeedsTheMetadataPath pins that the bridge is grounded in a REAL IMDS read, not in
// any mention of a role. An SSRF that never touched the metadata service must not manufacture a
// cloud link just because a role name appears somewhere in the text.
func TestIMDSBridgeNeedsTheMetadataPath(t *testing.T) {
	plain := Finding{Title: "SSRF to internal host", Description: "fetched http://10.0.0.5/status — no metadata access"}
	for _, e := range extractEntities(plain) {
		if e.Kind == EntIAMRole {
			t.Errorf("an SSRF with no IMDS read produced an iam_role bridge entity (%q) — the chain would be ungrounded", e.Value)
		}
	}
}
