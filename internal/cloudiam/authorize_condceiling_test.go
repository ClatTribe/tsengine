package cloudiam

import "testing"

// TestAuthorize_ConditionedCeilingDenyIsNotDefinitive: an SCP / permission-boundary Deny gated by a
// Condition is NOT a definitive deny. scanCeiling ignored the condition and set deny unconditionally, so
// a conditioned org-guardrail deny (e.g. "Deny s3:* unless aws:SourceIp is in the corp range") read as a
// definitive ExplicitDeny → over-pruned a genuinely-reachable edge (§10: keep on uncertain; drop only on
// a DEFINITIVE deny — the #822/#824/#825 class, now in the ceiling path). Since ceiling conditions aren't
// evaluated in this subset, a CONDITIONED ceiling deny must not definitively deny; only an UNCONDITIONAL
// one does. The identity/resource path (applyStatement) already handles this correctly.
func TestAuthorize_ConditionedCeilingDenyIsNotDefinitive(t *testing.T) {
	identity := mustDoc(t, `{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}`)
	req := Request{Principal: "arn:aws:iam::111:role/r", Action: "s3:GetObject", Resource: "arn:aws:s3:::b/o"}

	// SCP: allow-all + a CONDITIONED deny. The deny may not apply → must not definitively deny.
	scpCond := mustDoc(t, `{"Statement":[
		{"Effect":"Allow","Action":"*","Resource":"*"},
		{"Effect":"Deny","Action":"s3:GetObject","Resource":"*","Condition":{"IpAddress":{"aws:SourceIp":"203.0.113.0/24"}}}
	]}`)
	if dec, _ := Authorize(req, PolicySet{Identity: []*Document{identity}, SCPs: []*Document{scpCond}, SameAccount: true}); dec != Allow {
		t.Fatalf("a CONDITIONED SCP deny must not definitively deny a reachable edge; want Allow, got %v", dec)
	}

	// Boundary with a conditioned deny — same rule.
	bndCond := mustDoc(t, `{"Statement":[
		{"Effect":"Allow","Action":"*","Resource":"*"},
		{"Effect":"Deny","Action":"s3:GetObject","Resource":"*","Condition":{"IpAddress":{"aws:SourceIp":"203.0.113.0/24"}}}
	]}`)
	if dec, _ := Authorize(req, PolicySet{Identity: []*Document{identity}, Boundary: bndCond, SameAccount: true}); dec != Allow {
		t.Fatalf("a CONDITIONED boundary deny must not definitively deny; want Allow, got %v", dec)
	}

	// An UNCONDITIONAL SCP deny still wins (unchanged).
	scpUncond := mustDoc(t, `{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"},{"Effect":"Deny","Action":"s3:GetObject","Resource":"*"}]}`)
	if dec, _ := Authorize(req, PolicySet{Identity: []*Document{identity}, SCPs: []*Document{scpUncond}, SameAccount: true}); dec != ExplicitDeny {
		t.Errorf("an unconditional SCP deny must still win, got %v", dec)
	}
}
