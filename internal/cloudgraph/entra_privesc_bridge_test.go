package cloudgraph

import (
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/internal/azureiam"
)

// TestAddAzureEntraPrivescEdges: a principal that can escalate on the ENTRA (Azure AD) graph plane —
// here by holding Application.ReadWrite.All (add a secret to any privileged app) — gets a privesc → admin
// edge, while a read-only principal does not. This is the distinct identity-plane twin of the ARM edge:
// the escalation is invisible to the ARM Microsoft.* catalog, so without it the attack path is missed.
func TestAddAzureEntraPrivescEdges(t *testing.T) {
	s := New("sub-abc", "azure")
	s.AddNode(&Node{ID: "az-user-1", Kind: KindPrincipal, Name: "app-admin"})
	s.AddNode(&Node{ID: "az-user-2", Kind: KindPrincipal, Name: "reader"})

	can := map[string]func(string) bool{
		"az-user-1": azureiam.EntraCanFromGrants([]string{"Application.ReadWrite.All"}, nil),
		"az-user-2": azureiam.EntraCanFromGrants([]string{"Directory.Read.All"}, nil),
	}
	s.AddAzureEntraPrivescEdges(can)

	if s.Node(AdminID) == nil {
		t.Fatal("an Entra-escalation-capable principal should create the synthetic admin node")
	}
	var sawEscalator, sawReader bool
	var detail string
	for _, e := range s.Edges {
		if e.Kind != EdgePrivesc {
			continue
		}
		if e.From == "az-user-1" && e.To == AdminID {
			sawEscalator = true
			detail = e.Detail
		}
		if e.From == "az-user-2" {
			sawReader = true
		}
	}
	if !sawEscalator {
		t.Error("az-user-1 (Application.ReadWrite.All) should get an Entra privesc → admin edge")
	}
	if sawReader {
		t.Error("az-user-2 (read-only) must NOT get a privesc edge")
	}
	// the edge Detail names the Entra technique — distinguishable from an ARM escalation in the graph.
	if !strings.Contains(detail, "Entra:") {
		t.Errorf("the edge Detail should name the Entra technique, got %q", detail)
	}
}

// TestEntraAndARMPrivesc_BothPlanesOnOneSnapshot: the two planes coexist without conflation — an
// ARM-privesc principal and an Entra-privesc principal each get their own privesc edge, labeled by plane.
func TestEntraAndARMPrivesc_BothPlanesOnOneSnapshot(t *testing.T) {
	s := New("sub-abc", "azure")
	s.AddNode(&Node{ID: "arm-p", Kind: KindPrincipal, Name: "arm-escalator"})
	s.AddNode(&Node{ID: "entra-p", Kind: KindPrincipal, Name: "entra-escalator"})

	s.AddAzurePrivescEdges(map[string]func(string) bool{
		"arm-p": func(a string) bool { return a == "Microsoft.Authorization/roleAssignments/write" },
	})
	s.AddAzureEntraPrivescEdges(map[string]func(string) bool{
		"entra-p": azureiam.EntraCanFromGrants([]string{"RoleManagement.ReadWrite.Directory"}, nil),
	})

	arm, entra := "", ""
	for _, e := range s.Edges {
		if e.Kind != EdgePrivesc {
			continue
		}
		switch e.From {
		case "arm-p":
			arm = e.Detail
		case "entra-p":
			entra = e.Detail
		}
	}
	if arm == "" || strings.Contains(arm, "Entra:") {
		t.Errorf("the ARM principal should have an ARM-labeled privesc edge, got %q", arm)
	}
	if !strings.Contains(entra, "Entra:") {
		t.Errorf("the Entra principal should have an Entra-labeled privesc edge, got %q", entra)
	}
}
