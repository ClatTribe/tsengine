package cloudgraph

import "testing"

func TestInventoryRoundTrip(t *testing.T) {
	// Ingest an inventory, serialize the snapshot back, re-ingest: the graph
	// (by content hash) must be identical — so exporting a synthetic account as
	// inventory JSON loses nothing.
	inv := Inventory{
		AccountID: "acct", Provider: "aws",
		Resources: []InvResource{
			{ID: "internet", Kind: KindNetwork, Name: "internet"},
			{ID: "alb", Kind: KindResource, Public: true, Name: "alb"},
			{ID: "role", Kind: KindPrincipal, Name: "role"},
			{ID: "pii", Kind: KindData, Sensitive: SensHigh, Name: "pii"},
		},
		Reaches:  []InvReach{{From: "internet", To: "alb"}},
		RunsAs:   []InvRunsAs{{Compute: "alb", Principal: "role"}},
		Grants:   []InvGrant{{Principal: "role", Resource: "pii", Condition: "mfa"}},
		Privescs: []InvPrivesc{{Principal: "role", Target: "admin", Detail: "CreateAccessKey"}},
	}
	s1 := Ingest(inv)
	s2 := Ingest(s1.ToInventory())
	if s1.Hash() != s2.Hash() {
		t.Errorf("round-trip changed the graph:\n %s\n %s", s1.Hash(), s2.Hash())
	}
	// the conditioned grant must survive the round-trip
	var found bool
	for _, e := range s2.Edges {
		if e.Kind == EdgeHasAccess && e.From == "role" && e.To == "pii" && e.Condition == "mfa" {
			found = true
		}
	}
	if !found {
		t.Error("conditioned has_access edge lost in round-trip")
	}
}
