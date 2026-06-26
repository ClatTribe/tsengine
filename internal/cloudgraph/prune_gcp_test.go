package cloudgraph

import "testing"

// GCP SA-impersonation pruning: an over-approximated (principal → SA) assume edge is DROPPED when the SA's
// IAM policy grants the principal no impersonation permission, and KEPT when it does — closing the
// "cloudiam is AWS-only, GCP edges never pruned" gap with the new gcpiam evaluator.
func TestPrune_GCPImpersonationDeniedDropsEdge(t *testing.T) {
	// The SA's policy grants token-creator to a DIFFERENT user, not to the attacker.
	pol := `{"bindings":[{"role":"roles/iam.serviceAccountTokenCreator","members":["user:trusted@acme.com"]}],` +
		`"roles":{"roles/iam.serviceAccountTokenCreator":["iam.serviceAccounts.getAccessToken"]}}`
	s := New("proj", "gcp")
	s.AddNode(&Node{ID: "user:attacker@acme.com", Kind: KindPrincipal})
	s.AddNode(&Node{ID: "sa", Kind: KindPrincipal, Type: "ServiceAccount", Attrs: map[string]string{"gcp_iam_policy": pol}})
	s.AddEdge(Edge{From: "user:attacker@acme.com", To: "sa", Kind: EdgeAssumeRole})

	s.PruneUnauthorized()
	if len(s.Edges) != 0 {
		t.Fatalf("the impersonation edge should be pruned (attacker can't impersonate the SA), got %d edges", len(s.Edges))
	}
}

func TestPrune_GCPImpersonationAllowedKeepsEdge(t *testing.T) {
	pol := `{"bindings":[{"role":"roles/iam.serviceAccountTokenCreator","members":["user:attacker@acme.com"]}],` +
		`"roles":{"roles/iam.serviceAccountTokenCreator":["iam.serviceAccounts.getAccessToken"]}}`
	s := New("proj", "gcp")
	s.AddNode(&Node{ID: "user:attacker@acme.com", Kind: KindPrincipal})
	s.AddNode(&Node{ID: "sa", Kind: KindPrincipal, Attrs: map[string]string{"gcp_iam_policy": pol}})
	s.AddEdge(Edge{From: "user:attacker@acme.com", To: "sa", Kind: EdgeAssumeRole})

	s.PruneUnauthorized()
	if len(s.Edges) != 1 {
		t.Fatalf("the impersonation edge is authorized and must be kept, got %d edges", len(s.Edges))
	}
}

// No GCP policy attached → keep (recall preserved on missing data, like the AWS path).
func TestPrune_GCPNoPolicyKeepsEdge(t *testing.T) {
	s := New("proj", "gcp")
	s.AddNode(&Node{ID: "user:x@acme.com", Kind: KindPrincipal})
	s.AddNode(&Node{ID: "sa", Kind: KindPrincipal})
	s.AddEdge(Edge{From: "user:x@acme.com", To: "sa", Kind: EdgeAssumeRole})
	s.PruneUnauthorized()
	if len(s.Edges) != 1 {
		t.Fatalf("no attached policy → edge kept, got %d edges", len(s.Edges))
	}
}

// Azure RBAC pruning: an over-approximated assume/escalate edge to a target identity is DROPPED when the
// target's RBAC policy grants the source no privileged (role-assignment) action, and KEPT when it does.
func TestPrune_AzureEscalationDeniedDropsEdge(t *testing.T) {
	// The policy makes the attacker only a Reader on the target → no escalate/assign action.
	pol := `{"assignments":[{"role":"Reader","principals":["user:attacker@acme.com"]}]}`
	s := New("sub", "azure")
	s.AddNode(&Node{ID: "user:attacker@acme.com", Kind: KindPrincipal})
	s.AddNode(&Node{ID: "mi", Kind: KindPrincipal, Type: "ManagedIdentity", Attrs: map[string]string{"azure_rbac_policy": pol}})
	s.AddEdge(Edge{From: "user:attacker@acme.com", To: "mi", Kind: EdgeAssumeRole})
	s.PruneUnauthorized()
	if len(s.Edges) != 0 {
		t.Fatalf("a Reader can't escalate to the identity → edge pruned, got %d edges", len(s.Edges))
	}
}

func TestPrune_AzureEscalationAllowedKeepsEdge(t *testing.T) {
	pol := `{"assignments":[{"role":"Owner","principals":["user:attacker@acme.com"]}]}`
	s := New("sub", "azure")
	s.AddNode(&Node{ID: "user:attacker@acme.com", Kind: KindPrincipal})
	s.AddNode(&Node{ID: "mi", Kind: KindPrincipal, Attrs: map[string]string{"azure_rbac_policy": pol}})
	s.AddEdge(Edge{From: "user:attacker@acme.com", To: "mi", Kind: EdgeAssumeRole})
	s.PruneUnauthorized()
	if len(s.Edges) != 1 {
		t.Fatalf("an Owner can escalate → edge kept, got %d edges", len(s.Edges))
	}
}
