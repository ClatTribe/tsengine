package cloudgraph

import (
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/internal/azureiam"
)

// privescToAdmin reports whether the snapshot has a privesc → admin edge from `from`.
func privescToAdmin(s *Snapshot, from string) (bool, string) {
	for _, e := range s.Edges {
		if e.Kind == EdgePrivesc && e.To == AdminID && e.From == from {
			return true, e.Detail
		}
	}
	return false, ""
}

// TestAddEntraOwnershipEdges_PrivilegedSP: owning a PRIVILEGED service principal is an escalation (add a
// credential → act as it → inherit its privilege) — the owner gets a privesc → admin edge. Owning a
// NON-privileged SP adds nothing, and self-ownership adds nothing. This is the relationship half of Entra
// privesc, invisible to the permission-only view.
func TestAddEntraOwnershipEdges_PrivilegedSP(t *testing.T) {
	s := New("tenant-1", "azure")
	s.AddNode(&Node{ID: "user-alice", Kind: KindPrincipal, Name: "alice"})
	s.AddNode(&Node{ID: "sp-privileged", Kind: KindPrincipal, Name: "graph-admin-sp", Privileged: true})
	s.AddNode(&Node{ID: "sp-benign", Kind: KindPrincipal, Name: "reporting-sp"})
	s.AddNode(&Node{ID: "user-bob", Kind: KindPrincipal, Name: "bob"})

	s.AddEntraOwnershipEdges(map[string][]string{
		"user-alice":    {"sp-privileged"}, // owns an admin-privileged SP → escalates
		"user-bob":      {"sp-benign"},     // owns a non-privileged SP → nothing
		"sp-privileged": {"sp-privileged"}, // self-ownership → nothing
	})

	if ok, detail := privescToAdmin(s, "user-alice"); !ok {
		t.Error("owning a privileged SP must add a privesc → admin edge")
	} else if !strings.Contains(detail, "OwnerOfPrivilegedSP") || !strings.Contains(detail, "sp-privileged") {
		t.Errorf("the edge should name the ownership technique + the owned SP, got %q", detail)
	}
	if ok, _ := privescToAdmin(s, "user-bob"); ok {
		t.Error("owning a NON-privileged SP must NOT escalate")
	}
	if ok, _ := privescToAdmin(s, "sp-privileged"); ok {
		t.Error("self-ownership must not create a self-escalation edge")
	}
}

// TestAddEntraOwnershipEdges_InheritsPermissionEscalation: if the owned SP can ITSELF escalate (it holds a
// graph permission that AddAzureEntraPrivescEdges turned into a privesc → admin edge), its owner inherits
// that path. Proves the two Entra halves compose when ownership is applied AFTER the permission adder.
func TestAddEntraOwnershipEdges_InheritsPermissionEscalation(t *testing.T) {
	s := New("tenant-1", "azure")
	s.AddNode(&Node{ID: "user-eve", Kind: KindPrincipal, Name: "eve"})
	s.AddNode(&Node{ID: "sp-escalator", Kind: KindPrincipal, Name: "app-with-approle-write"})

	// the SP itself can escalate via a graph permission (not marked Privileged, but permission-capable).
	s.AddAzureEntraPrivescEdges(map[string]func(string) bool{
		"sp-escalator": azureiam.EntraCanFromGrants([]string{"AppRoleAssignment.ReadWrite.All"}, nil),
	})
	// eve owns that SP → she inherits its escalation.
	s.AddEntraOwnershipEdges(map[string][]string{"user-eve": {"sp-escalator"}})

	if ok, _ := privescToAdmin(s, "sp-escalator"); !ok {
		t.Fatal("precondition: the permission-escalating SP should have its own privesc edge")
	}
	if ok, detail := privescToAdmin(s, "user-eve"); !ok {
		t.Error("owning a self-escalating SP must let the owner inherit the escalation")
	} else if !strings.Contains(detail, "OwnerOfPrivilegedSP") {
		t.Errorf("the inherited edge should name the ownership technique, got %q", detail)
	}
}
