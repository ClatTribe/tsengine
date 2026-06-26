package cloudgraph

import "testing"

// Service-coupling closes the "how does the attacker reach the compute" gap: a public API Gateway that
// TRIGGERS a Lambda that RUNS_AS a role with HAS_ACCESS to a sensitive bucket is now a discoverable
// internet→data attack path. Before EdgeTriggers the chain dead-ended at the gateway (the graph knew the
// Lambda's role but not that the gateway could invoke it).
func TestTriggers_InternetViaServiceCouplingReachesData(t *testing.T) {
	inv := Inventory{
		AccountID: "111", Provider: "aws",
		Resources: []InvResource{
			{ID: "apigw", Kind: KindResource, Type: "AWS::ApiGateway::RestApi", Public: true},
			{ID: "fn", Kind: KindResource, Type: "AWS::Lambda::Function"},
			{ID: "role", Kind: KindPrincipal, Type: "AWS::IAM::Role"},
			{ID: "bucket", Kind: KindData, Type: "AWS::S3::Bucket", Sensitive: SensHigh},
		},
		Reaches:  []InvReach{{From: InternetID, To: "apigw"}},
		Triggers: []InvTrigger{{Source: "apigw", Compute: "fn"}},
		RunsAs:   []InvRunsAs{{Compute: "fn", Principal: "role"}},
		Grants:   []InvGrant{{Principal: "role", Resource: "bucket"}},
	}
	s := Ingest(inv)
	paths := s.FindPaths(InternetID, SensitiveData, AllAttackEdges, 8, 50)
	if len(paths) == 0 {
		t.Fatal("internet → apigw → (triggers) fn → role → bucket should be a discovered path")
	}
	// The discovered path must traverse the triggers edge.
	var sawTrigger bool
	for _, e := range paths[0].Edges {
		if e.Kind == EdgeTriggers {
			sawTrigger = true
		}
	}
	if !sawTrigger {
		t.Errorf("the path should include the service-coupling (triggers) edge: %+v", paths[0].Edges)
	}

	// Round-trip: the triggers edge survives ToInventory → Ingest (reproducibility).
	if got := s.ToInventory().Triggers; len(got) != 1 || got[0].Source != "apigw" || got[0].Compute != "fn" {
		t.Errorf("triggers edge should round-trip via ToInventory, got %+v", got)
	}
}

// Without the trigger edge, the internet cannot reach the data (the gap this closes) — the chain dead-ends
// at the gateway. Grounding: no coupling emitted → no false path.
func TestTriggers_NoCouplingNoPath(t *testing.T) {
	inv := Inventory{
		AccountID: "111", Provider: "aws",
		Resources: []InvResource{
			{ID: "apigw", Kind: KindResource, Public: true},
			{ID: "fn", Kind: KindResource},
			{ID: "role", Kind: KindPrincipal},
			{ID: "bucket", Kind: KindData, Sensitive: SensHigh},
		},
		Reaches: []InvReach{{From: InternetID, To: "apigw"}},
		RunsAs:  []InvRunsAs{{Compute: "fn", Principal: "role"}},
		Grants:  []InvGrant{{Principal: "role", Resource: "bucket"}},
	}
	s := Ingest(inv)
	if paths := s.FindPaths(InternetID, SensitiveData, AllAttackEdges, 8, 50); len(paths) != 0 {
		t.Errorf("no service coupling → the internet must NOT reach the data, got %d paths", len(paths))
	}
}
