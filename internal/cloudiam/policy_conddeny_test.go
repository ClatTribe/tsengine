package cloudiam

import "testing"

// TestEval_ConditionedDenyIsNotDefinitive: a Deny gated by a Condition we can't resolve must NOT read
// as a definitive ExplicitDeny. The condition may not hold at runtime, so treating a conditioned deny
// as an unconditional one over-denies — and since Eval/Allows feeds the privesc-technique detector
// (privesc.go) and the ingest's edge computation, that DROPS a possibly-reachable path (§10: keep on
// uncertain, drop only on a DEFINITIVE deny). The sibling evaluator authorize.go already treats an
// indeterminate deny condition as not-denying; Eval must match. The grant becomes conditional (allowed
// unless the deny fires), not denied.
func TestEval_ConditionedDenyIsNotDefinitive(t *testing.T) {
	allow := mustParse(t, `{"Statement":[{"Effect":"Allow","Action":"iam:AttachUserPolicy","Resource":"*"}]}`)
	condDeny := mustParse(t, `{"Statement":[{"Effect":"Deny","Action":"iam:AttachUserPolicy","Resource":"*","Condition":{"Bool":{"aws:MultiFactorAuthPresent":"false"}}}]}`)

	dec, cond := Eval("iam:AttachUserPolicy", "*", allow, condDeny)
	if dec == ExplicitDeny {
		t.Fatalf("a conditioned Deny must not read as a definitive ExplicitDeny (the condition may not hold)")
	}
	if dec != Allow {
		t.Fatalf("with an Allow present and only a conditioned Deny, the grant stands (conditionally); got %v", dec)
	}
	if !cond {
		t.Errorf("a grant shadowed by a conditioned Deny must be marked conditional (allowed unless the deny fires)")
	}

	// An UNCONDITIONAL Deny still definitively denies (unchanged).
	uncondDeny := mustParse(t, `{"Statement":[{"Effect":"Deny","Action":"iam:AttachUserPolicy","Resource":"*"}]}`)
	if dec, _ := Eval("iam:AttachUserPolicy", "*", allow, uncondDeny); dec != ExplicitDeny {
		t.Errorf("an unconditional Deny must still win: got %v", dec)
	}

	// A conditioned Deny with NO Allow present is still not a grant (implicit deny).
	if dec, _ := Eval("iam:AttachUserPolicy", "*", condDeny); dec != ImplicitDeny {
		t.Errorf("a conditioned Deny alone grants nothing: got %v", dec)
	}
}
