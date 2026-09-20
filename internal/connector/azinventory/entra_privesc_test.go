package azinventory

import (
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/internal/cloudgraph"
)

// THE HOLE THIS CLOSES (ADR 0031 D2a, second half). §10 claims Azure escalation is discovered
// symmetrically, and the ARM half was wired — but the ENTRA (Azure AD) graph plane was not: RawAzure
// carried no Graph-permission / directory-role / ownership field, so azureiam.DetectEntraPrivesc and
// the two cloudgraph Entra edge builders (all tested) had no data source, and an Azure tenant owned
// through Entra produced ZERO attack-path edges. This drives the whole ingest path — Build → Ingest —
// and asserts the escalation reaches a real privesc → admin edge in the snapshot.
func TestDeriveEntraPrivesc_GraphPermissionEscalatesThroughToASnapshotEdge(t *testing.T) {
	inv := Build(RawAzure{
		SubscriptionID: "sub-1",
		Principals: []RawAzPrincipal{
			{ID: "sp:app-admin", Name: "app-admin", GraphPermissions: []string{"Application.ReadWrite.All"}},
			{ID: "sp:reader", Name: "reader", GraphPermissions: []string{"Directory.Read.All"}},
		},
	})

	// The escalator has an Entra-labelled privesc record; the reader has none.
	var esc *cloudgraph.InvPrivesc
	for i := range inv.Privescs {
		if inv.Privescs[i].Principal == "sp:reader" {
			t.Errorf("a read-only Graph permission must NOT escalate: %+v", inv.Privescs[i])
		}
		if inv.Privescs[i].Principal == "sp:app-admin" {
			esc = &inv.Privescs[i]
		}
	}
	if esc == nil {
		t.Fatal("Application.ReadWrite.All did not produce an Entra escalation — the plane is still unwired")
	}
	if esc.Target != cloudgraph.AdminID || !strings.Contains(esc.Detail, "Entra:") {
		t.Errorf("edge must reach admin and name the Entra technique: %+v", esc)
	}
	if esc.Condition != "" {
		t.Errorf("Entra app-role grants carry no IAM condition, so the edge is unconditional, got %q", esc.Condition)
	}

	// End to end: Ingest turns the record into a real graph edge.
	snap := cloudgraph.Ingest(inv)
	found := false
	for _, e := range snap.Edges {
		if e.Kind == cloudgraph.EdgePrivesc && e.From == "sp:app-admin" && e.To == cloudgraph.AdminID {
			found = true
		}
	}
	if !found {
		t.Error("the Entra escalation did not survive Ingest into a snapshot privesc → admin edge")
	}
}

// The RELATIONSHIP half: owning a principal that escalates (here, by ARM Owner) inherits the
// escalation — the "Owns → AZServicePrincipal" path — while owning a benign principal does not.
func TestDeriveEntraPrivesc_OwningAnEscalatingPrincipalInheritsIt(t *testing.T) {
	inv := Build(RawAzure{
		SubscriptionID: "sub-1",
		Principals: []RawAzPrincipal{
			{ID: "user:alice", Name: "alice", Owns: []string{"sp:privileged"}},
			{ID: "user:bob", Name: "bob", Owns: []string{"sp:benign"}},
			{ID: "sp:privileged", Name: "deployer"},
			{ID: "sp:benign", Name: "reporting"},
		},
		// sp:privileged escalates via ARM Owner; the ownership half must inherit that.
		RoleAssignments: []RawAzAssignment{{Role: "Owner", Principals: []string{"sp:privileged"}}},
	})

	owns := func(who string) *cloudgraph.InvPrivesc {
		for i := range inv.Privescs {
			if inv.Privescs[i].Principal == who && strings.Contains(inv.Privescs[i].Detail, "OwnerOfPrivilegedSP") {
				return &inv.Privescs[i]
			}
		}
		return nil
	}
	if a := owns("user:alice"); a == nil {
		t.Error("owning a privilege-escalating SP must inherit the escalation")
	} else if !strings.Contains(a.Detail, "sp:privileged") {
		t.Errorf("the ownership edge must name the owned SP: %q", a.Detail)
	}
	if owns("user:bob") != nil {
		t.Error("owning a NON-escalating principal must NOT escalate")
	}
}

// Grounded (§10): a subscription with no Entra holdings and no ownership produces no Entra edges and
// no synthetic admin — "we could not see the Entra plane" is not "the tenant is safe".
func TestDeriveEntraPrivesc_NoHoldingsNoEdges(t *testing.T) {
	inv := Build(RawAzure{
		SubscriptionID: "sub-1",
		Principals:     []RawAzPrincipal{{ID: "sp:plain", Name: "plain"}},
	})
	for _, pe := range inv.Privescs {
		if strings.Contains(pe.Detail, "Entra:") {
			t.Errorf("no Entra holdings must yield no Entra escalation, got %+v", pe)
		}
	}
}
