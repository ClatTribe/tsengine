package gcpiam

import "testing"

// TestAuthorize_UncertainGroupDenyIsNotDefinitive: a Deny rule targeting a GROUP whose membership we
// can't resolve is NOT a definitive deny — the member may not be in the group. The deny loop discarded
// memberMatch's `certain` bool and returned ExplicitDeny on the mere (uncertain) hit, over-pruning a
// possibly-reachable edge. Per §10 (and this file's own contract), only a DEFINITIVE deny drops an edge;
// an uncertain deny must keep it (as a conditional allow). The allow side already treats an uncertain
// group match as conditional — the deny side must be symmetric.
func TestAuthorize_UncertainGroupDenyIsNotDefinitive(t *testing.T) {
	ps := PolicySet{
		Resource: &Resource{Bindings: []Binding{
			{Role: "roles/owner", Members: []string{"user:alice@x.com"}},
		}},
		Denies: []DenyRule{
			{DeniedPermissions: []string{"storage.objects.get"}, DeniedPrincipals: []string{"group:admins@x.com"}},
		},
	}
	dec, cond := Authorize(Request{Member: "user:alice@x.com", Permission: "storage.objects.get"}, ps)
	if dec == ExplicitDeny {
		t.Fatalf("an uncertain group-membership deny must not read as a definitive ExplicitDeny (member may not be in the group)")
	}
	if dec != Allow || !cond {
		t.Errorf("a firm allow shadowed by a POSSIBLE group deny must be Allow+conditional (keeps the edge), got dec=%v cond=%v", dec, cond)
	}

	// An EXACT-member deny still definitively denies (unchanged).
	ps.Denies[0].DeniedPrincipals = []string{"user:alice@x.com"}
	if dec, _ := Authorize(Request{Member: "user:alice@x.com", Permission: "storage.objects.get"}, ps); dec != ExplicitDeny {
		t.Errorf("an exact-member deny must still be ExplicitDeny, got %v", dec)
	}

	// An allUsers deny is also certain → definitive.
	ps.Denies[0].DeniedPrincipals = []string{"allUsers"}
	if dec, _ := Authorize(Request{Member: "user:alice@x.com", Permission: "storage.objects.get"}, ps); dec != ExplicitDeny {
		t.Errorf("an allUsers deny must be ExplicitDeny, got %v", dec)
	}
}
