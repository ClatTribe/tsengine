package cloudiam

import "testing"

func mustDoc(t *testing.T, s string) *Document {
	t.Helper()
	d, err := Parse([]byte(s))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return d
}

// Resource-based policy grants access the identity policy does NOT — the classic
// cross-principal S3 bucket-policy grant. Authorize must allow it (same-account).
func TestAuthorize_ResourcePolicyGrants(t *testing.T) {
	bucketPolicy := mustDoc(t, `{"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::111111111111:role/app"},"Action":"s3:GetObject","Resource":"arn:aws:s3:::data/*"}]}`)
	req := Request{Principal: "arn:aws:iam::111111111111:role/app", Action: "s3:GetObject", Resource: "arn:aws:s3:::data/obj"}

	// No identity policy at all — access must come from the resource policy.
	if allowed, _ := Permits(req, PolicySet{ResourcePolicy: bucketPolicy, SameAccount: true}); !allowed {
		t.Error("same-account resource policy granting the principal must allow access")
	}
	// A different principal must NOT be granted.
	other := req
	other.Principal = "arn:aws:iam::111111111111:role/intruder"
	if allowed, _ := Permits(other, PolicySet{ResourcePolicy: bucketPolicy, SameAccount: true}); allowed {
		t.Error("resource policy must not grant a principal it does not name")
	}
}

// An SCP is an org ceiling: even with a full identity allow, an SCP Deny wins.
func TestAuthorize_SCPDenyWins(t *testing.T) {
	identity := mustDoc(t, `{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`)
	scp := mustDoc(t, `{"Statement":[{"Effect":"Deny","Action":"s3:*","Resource":"*"}]}`)
	req := Request{Principal: "p", Action: "s3:GetObject", Resource: "arn:aws:s3:::x"}

	if allowed, _ := Permits(req, PolicySet{Identity: []*Document{identity}, SameAccount: true}); !allowed {
		t.Fatal("sanity: admin identity should allow without the SCP")
	}
	if dec, _ := Authorize(req, PolicySet{Identity: []*Document{identity}, SCPs: []*Document{scp}, SameAccount: true}); dec != ExplicitDeny {
		t.Errorf("SCP Deny must override an identity Allow, got %v", dec)
	}
}

// A permission boundary is a ceiling: an action the boundary doesn't permit is
// denied even if the identity policy allows it.
func TestAuthorize_BoundaryCeiling(t *testing.T) {
	identity := mustDoc(t, `{"Statement":[{"Effect":"Allow","Action":"iam:CreatePolicyVersion","Resource":"*"}]}`)
	boundary := mustDoc(t, `{"Statement":[{"Effect":"Allow","Action":"s3:Get*","Resource":"*"}]}`)
	req := Request{Principal: "p", Action: "iam:CreatePolicyVersion", Resource: "*"}
	if dec, _ := Authorize(req, PolicySet{Identity: []*Document{identity}, Boundary: boundary, SameAccount: true}); dec == Allow {
		t.Error("permission boundary must block an action it does not permit")
	}
}

// Condition evaluation: an allow gated by MFA is satisfied only when the context
// carries MFA; otherwise it is conditional (config-possible, not confirmed).
func TestAuthorize_ConditionMFA(t *testing.T) {
	identity := mustDoc(t, `{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*","Condition":{"Bool":{"aws:MultiFactorAuthPresent":"true"}}}]}`)
	base := Request{Principal: "p", Action: "s3:GetObject", Resource: "arn:aws:s3:::x"}

	// MFA present → real allow.
	withMFA := base
	withMFA.Context = map[string]string{"aws:MultiFactorAuthPresent": "true"}
	if allowed, cond := Permits(withMFA, PolicySet{Identity: []*Document{identity}, SameAccount: true}); !allowed || cond {
		t.Errorf("with MFA present: want allowed&&!conditional, got allowed=%v cond=%v", allowed, cond)
	}
	// MFA explicitly absent → not allowed (condition evaluable and false).
	noMFA := base
	noMFA.Context = map[string]string{"aws:MultiFactorAuthPresent": "false"}
	if allowed, _ := Permits(noMFA, PolicySet{Identity: []*Document{identity}, SameAccount: true}); allowed {
		t.Error("with MFA false: the MFA-gated allow must not apply")
	}
	// No MFA context at all → indeterminate → conditional (config-possible).
	if allowed, cond := Permits(base, PolicySet{Identity: []*Document{identity}, SameAccount: true}); !(allowed && cond) {
		t.Errorf("with no MFA context: want conditionally-allowed, got allowed=%v cond=%v", allowed, cond)
	}
}

// Condition evaluation: IP allow-list (IpAddress) gates on aws:SourceIp.
func TestAuthorize_ConditionSourceIP(t *testing.T) {
	identity := mustDoc(t, `{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*","Condition":{"IpAddress":{"aws:SourceIp":"10.0.0.0/8"}}}]}`)
	in := Request{Principal: "p", Action: "s3:GetObject", Resource: "x", Context: map[string]string{"aws:SourceIp": "10.1.2.3"}}
	out := Request{Principal: "p", Action: "s3:GetObject", Resource: "x", Context: map[string]string{"aws:SourceIp": "203.0.113.9"}}
	if allowed, _ := Permits(in, PolicySet{Identity: []*Document{identity}, SameAccount: true}); !allowed {
		t.Error("source IP inside the allowed CIDR must allow")
	}
	if allowed, _ := Permits(out, PolicySet{Identity: []*Document{identity}, SameAccount: true}); allowed {
		t.Error("source IP outside the allowed CIDR must not allow")
	}
}

// Cross-account: access requires BOTH the identity policy (caller side) AND the
// resource policy (resource side) to allow.
func TestAuthorize_CrossAccountNeedsBoth(t *testing.T) {
	identity := mustDoc(t, `{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}`)
	req := Request{Principal: "arn:aws:iam::222222222222:role/app", Action: "s3:GetObject", Resource: "arn:aws:s3:::data/obj"}

	// Identity allows but no resource policy → cross-account denied.
	if allowed, _ := Permits(req, PolicySet{Identity: []*Document{identity}, SameAccount: false}); allowed {
		t.Error("cross-account access needs the resource policy too")
	}
	// Both sides allow → granted.
	resPol := mustDoc(t, `{"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::222222222222:role/app"},"Action":"s3:GetObject","Resource":"arn:aws:s3:::data/*"}]}`)
	if allowed, _ := Permits(req, PolicySet{Identity: []*Document{identity}, ResourcePolicy: resPol, SameAccount: false}); !allowed {
		t.Error("cross-account access with both identity + resource allow must be granted")
	}
}
