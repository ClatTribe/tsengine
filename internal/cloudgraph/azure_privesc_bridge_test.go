package cloudgraph

import "testing"

func TestAddAzurePrivescEdges(t *testing.T) {
	s := New("sub-abc", "azure")
	s.AddNode(&Node{ID: "az-sp-1", Kind: KindPrincipal, Name: "deployer-sp"})
	s.AddNode(&Node{ID: "az-sp-2", Kind: KindPrincipal, Name: "reader-sp"})

	can := map[string]func(string) bool{
		"az-sp-1": func(a string) bool { return a == "Microsoft.Authorization/roleAssignments/write" },
		"az-sp-2": func(string) bool { return false },
	}
	s.AddAzurePrivescEdges(can)

	if s.Node(AdminID) == nil {
		t.Fatal("an escalation-capable Azure principal should create the synthetic admin node")
	}
	var sawEscalator, sawReader bool
	for _, e := range s.Edges {
		if e.Kind != EdgePrivesc {
			continue
		}
		if e.From == "az-sp-1" && e.To == AdminID {
			sawEscalator = true
		}
		if e.From == "az-sp-2" {
			sawReader = true
		}
	}
	if !sawEscalator {
		t.Error("az-sp-1 (roleAssignments/write) should get a privesc → admin edge")
	}
	if sawReader {
		t.Error("az-sp-2 (reader) must NOT get a privesc edge")
	}
}
