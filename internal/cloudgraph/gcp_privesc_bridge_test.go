package cloudgraph

import "testing"

func TestAddGCPPrivescEdges(t *testing.T) {
	s := New("proj-123", "gcp")
	s.AddNode(&Node{ID: "gcp-sa-1", Kind: KindPrincipal, Name: "deployer@proj.iam"})
	s.AddNode(&Node{ID: "gcp-sa-2", Kind: KindPrincipal, Name: "readonly@proj.iam"})

	can := map[string]func(string) bool{
		"gcp-sa-1": func(p string) bool { return p == "resourcemanager.projects.setIamPolicy" }, // can escalate
		"gcp-sa-2": func(string) bool { return false },                                          // cannot
	}
	s.AddGCPPrivescEdges(can)

	if s.Node(AdminID) == nil {
		t.Fatal("an escalation-capable GCP principal should create the synthetic admin node")
	}
	var sawEscalator, sawReadonly bool
	for _, e := range s.Edges {
		if e.Kind != EdgePrivesc {
			continue
		}
		if e.From == "gcp-sa-1" && e.To == AdminID {
			sawEscalator = true
		}
		if e.From == "gcp-sa-2" {
			sawReadonly = true
		}
	}
	if !sawEscalator {
		t.Error("gcp-sa-1 (setIamPolicy) should get a privesc → admin edge")
	}
	if sawReadonly {
		t.Error("gcp-sa-2 (read-only) must NOT get a privesc edge")
	}
}
