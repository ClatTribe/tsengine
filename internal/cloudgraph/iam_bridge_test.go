package cloudgraph

import (
	"testing"

	"github.com/ClatTribe/tsengine/internal/cloudiam"
)

func TestAddPrivescEdges_ReachesAdmin(t *testing.T) {
	s := New("acct", "aws")
	s.AddNode(&Node{ID: InternetID, Kind: KindNetwork})
	s.AddNode(&Node{ID: "alb", Kind: KindResource, Public: true})
	s.AddNode(&Node{ID: "ec2", Kind: KindResource})
	s.AddNode(&Node{ID: "low-role", Kind: KindPrincipal, Name: "low-role"})
	s.AddNode(&Node{ID: "ro-role", Kind: KindPrincipal, Name: "ro-role"})
	s.AddEdge(Edge{From: InternetID, To: "alb", Kind: EdgeNetworkReach})
	s.AddEdge(Edge{From: "alb", To: "ec2", Kind: EdgeNetworkReach})
	s.AddEdge(Edge{From: "ec2", To: "low-role", Kind: EdgeRunsAs})

	priv, _ := cloudiam.Parse([]byte(`{"Statement":[{"Effect":"Allow","Action":["iam:CreatePolicyVersion"],"Resource":"*"}]}`))
	ro, _ := cloudiam.Parse([]byte(`{"Statement":[{"Effect":"Allow","Action":["s3:GetObject"],"Resource":"*"}]}`))
	s.AddPrivescEdges(map[string][]*cloudiam.Document{
		"low-role": {priv}, // can escalate
		"ro-role":  {ro},   // cannot
	})

	if s.Node(AdminID) == nil {
		t.Fatal("admin node should be created when a principal can escalate")
	}
	// internet → alb → ec2 → low-role → privesc → admin (privileged)
	paths := s.FindPaths(InternetID, PrivilegedIdentity, AllAttackEdges, 8, 50)
	if len(paths) != 1 {
		t.Fatalf("want 1 path to admin via privesc, got %d", len(paths))
	}
	end := paths[0].Nodes[len(paths[0].Nodes)-1]
	if end != AdminID {
		t.Errorf("path should end at admin, ended at %q", end)
	}
	// ro-role must NOT have a privesc edge
	for _, e := range s.Edges {
		if e.From == "ro-role" && e.Kind == EdgePrivesc {
			t.Error("read-only role must not get a privesc edge")
		}
	}
}
