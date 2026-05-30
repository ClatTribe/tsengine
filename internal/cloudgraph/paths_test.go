package cloudgraph

import "testing"

// buildScenario wires the canonical kill-chain: internet → ALB → EC2(web-role)
// → assume → data-role → has-access → PII bucket. Plus a DECOY: a public bucket
// that holds non-sensitive data (config-bad, not real impact).
func buildScenario() *Snapshot {
	s := New("111122223333", "aws")
	s.AddNode(&Node{ID: InternetID, Kind: KindNetwork})
	s.AddNode(&Node{ID: "alb", Kind: KindResource, Type: "AWS::ELB::LB", Public: true})
	s.AddNode(&Node{ID: "ec2", Kind: KindResource, Type: "AWS::EC2::Instance"})
	s.AddNode(&Node{ID: "web-role", Kind: KindPrincipal, Type: "AWS::IAM::Role"})
	s.AddNode(&Node{ID: "data-role", Kind: KindPrincipal, Type: "AWS::IAM::Role"})
	s.AddNode(&Node{ID: "pii-bucket", Kind: KindData, Type: "AWS::S3::Bucket", Sensitive: SensHigh})
	// decoy
	s.AddNode(&Node{ID: "public-assets", Kind: KindData, Type: "AWS::S3::Bucket", Public: true, Sensitive: SensNone})

	s.AddEdge(Edge{From: InternetID, To: "alb", Kind: EdgeNetworkReach})
	s.AddEdge(Edge{From: "alb", To: "ec2", Kind: EdgeNetworkReach})
	s.AddEdge(Edge{From: "ec2", To: "web-role", Kind: EdgeRunsAs})
	s.AddEdge(Edge{From: "web-role", To: "data-role", Kind: EdgeAssumeRole, Condition: ""})
	s.AddEdge(Edge{From: "data-role", To: "pii-bucket", Kind: EdgeHasAccess})
	return s
}

func TestFindPaths_FindsPlantedChain(t *testing.T) {
	s := buildScenario()
	paths := s.FindPaths(InternetID, SensitiveData, AllAttackEdges, 8, 50)
	if len(paths) != 1 {
		t.Fatalf("want exactly 1 path internet→PII, got %d", len(paths))
	}
	p := paths[0]
	last := p.Nodes[len(p.Nodes)-1]
	if last != "pii-bucket" {
		t.Errorf("path should end at pii-bucket, ended at %q", last)
	}
	// internet→alb→ec2→web-role→data-role→pii-bucket = 5 edges, 6 nodes.
	if len(p.Edges) != 5 {
		t.Errorf("path should be 5 edges, got %d: %+v", len(p.Edges), p.Nodes)
	}
}

func TestFindPaths_DecoyNotReachable(t *testing.T) {
	s := buildScenario()
	// The non-sensitive public bucket is NOT high-sensitivity, so a
	// SensitiveData search must not return it.
	paths := s.FindPaths(InternetID, SensitiveData, AllAttackEdges, 8, 50)
	for _, p := range paths {
		for _, n := range p.Nodes {
			if n == "public-assets" {
				t.Errorf("decoy public-assets must not appear in a sensitive-data path")
			}
		}
	}
}

func TestFindPaths_RespectsEdgeAllowlist(t *testing.T) {
	s := buildScenario()
	// Without the assume_role edge kind, the chain to PII is broken.
	allow := map[EdgeKind]bool{EdgeNetworkReach: true, EdgeRunsAs: true, EdgeHasAccess: true}
	paths := s.FindPaths(InternetID, SensitiveData, allow, 8, 50)
	if len(paths) != 0 {
		t.Errorf("path should be broken without assume_role, got %d", len(paths))
	}
}

func TestFindPaths_DepthBoundTerminates(t *testing.T) {
	// A cycle must not loop forever (simple-path + depth bound).
	s := New("acct", "aws")
	s.AddNode(&Node{ID: "a", Kind: KindPrincipal})
	s.AddNode(&Node{ID: "b", Kind: KindPrincipal})
	s.AddNode(&Node{ID: "admin", Kind: KindPrincipal, Privileged: true})
	s.AddEdge(Edge{From: "a", To: "b", Kind: EdgeAssumeRole})
	s.AddEdge(Edge{From: "b", To: "a", Kind: EdgeAssumeRole}) // cycle
	s.AddEdge(Edge{From: "b", To: "admin", Kind: EdgePrivesc})
	paths := s.FindPaths("a", PrivilegedIdentity, AllAttackEdges, 8, 50)
	if len(paths) != 1 {
		t.Fatalf("want 1 path a→b→admin (cycle ignored), got %d", len(paths))
	}
}

func TestConditional(t *testing.T) {
	p := Path{Edges: []Edge{{Kind: EdgeAssumeRole, Condition: "aws:MultiFactorAuthPresent"}}}
	if !p.Conditional() {
		t.Error("path with a conditioned edge should be Conditional")
	}
	if (Path{Edges: []Edge{{Kind: EdgeHasAccess}}}).Conditional() {
		t.Error("path with no conditions should not be Conditional")
	}
}

func TestHash_DeterministicAndOrderIndependent(t *testing.T) {
	s1 := buildScenario()
	// Build the same graph with edges/nodes added in a different order.
	s2 := New("111122223333", "aws")
	s2.AddEdge(Edge{From: "data-role", To: "pii-bucket", Kind: EdgeHasAccess})
	s2.AddEdge(Edge{From: InternetID, To: "alb", Kind: EdgeNetworkReach})
	s2.AddEdge(Edge{From: "web-role", To: "data-role", Kind: EdgeAssumeRole})
	s2.AddEdge(Edge{From: "alb", To: "ec2", Kind: EdgeNetworkReach})
	s2.AddEdge(Edge{From: "ec2", To: "web-role", Kind: EdgeRunsAs})
	for _, n := range s1.Nodes {
		s2.AddNode(n)
	}
	if s1.Hash() != s2.Hash() {
		t.Errorf("hash must be order-independent:\n %s\n %s", s1.Hash(), s2.Hash())
	}
}
