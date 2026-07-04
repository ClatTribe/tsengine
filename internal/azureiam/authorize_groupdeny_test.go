package azureiam

import "testing"

// TestAuthorize_UncertainGroupDenyIsNotDefinitive: a DENY assignment targeting a GROUP whose membership
// we can't resolve is NOT a definitive deny — the principal may not be in the group. The deny loop
// discarded principalMatch's `certain` bool and returned ExplicitDeny on the mere (uncertain) hit,
// over-pruning a possibly-reachable edge. Per §10 (and this file's own contract) only a DEFINITIVE deny
// drops an edge; an uncertain deny keeps it (as a conditional allow). The ALLOW side already treats an
// uncertain group as conditional — the DENY side must be symmetric (the gcpiam #824 class, on Azure).
func TestAuthorize_UncertainGroupDenyIsNotDefinitive(t *testing.T) {
	ps := PolicySet{
		Scope: &Scope{Assignments: []Assignment{
			{Role: "Owner", Principals: []string{"user:alice@acme.com"}},
		}},
		Denies: []DenyAssignment{
			{Actions: []string{"Microsoft.Storage/storageAccounts/read"}, Principals: []string{"group:admins@acme.com"}},
		},
	}
	req := Request{Principal: "user:alice@acme.com", Action: "Microsoft.Storage/storageAccounts/read"}
	dec, cond := Authorize(req, ps)
	if dec == ExplicitDeny {
		t.Fatalf("an uncertain group deny-assignment must not read as a definitive ExplicitDeny (principal may not be in the group)")
	}
	if dec != Allow || !cond {
		t.Errorf("a firm Owner allow shadowed by a POSSIBLE group deny must be Allow+conditional (keeps the edge), got dec=%v cond=%v", dec, cond)
	}

	// An EXACT-principal deny still definitively denies (unchanged).
	ps.Denies[0].Principals = []string{"user:alice@acme.com"}
	if dec, _ := Authorize(req, ps); dec != ExplicitDeny {
		t.Errorf("an exact-principal deny must still be ExplicitDeny, got %v", dec)
	}
}
