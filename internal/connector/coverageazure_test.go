package connector

import (
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/internal/connector/azinventory"
)

// THE DEFECT. Azure returned an empty InventoryCoverage with a comment saying it "reports nothing
// rather than claiming completeness it has not checked" — but Summary() renders an empty coverage as
// "This snapshot carries everything the engine knows how to evaluate". The honest intention produced
// the confident claim it was trying to avoid.
func TestCoverAzure_NeverClaimsFullCoverage(t *testing.T) {
	// Even the richest snapshot this ingest can carry still has an unevaluated plane.
	raw := azinventory.RawAzure{
		SubscriptionID:  "sub-1",
		Principals:      []azinventory.RawAzPrincipal{{ID: "sp:a", Name: "a"}},
		VMs:             []azinventory.RawAzVM{{ID: "vm-1"}},
		Storage:         []azinventory.RawAzStorage{{Name: "st1"}},
		RoleAssignments: []azinventory.RawAzAssignment{{Role: "Owner", Principals: []string{"sp:a"}}},
	}
	c := CoverAzure(raw)
	if c.Complete() {
		t.Fatal("a full ARM snapshot reported complete coverage — the Entra plane is never carried by " +
			"this ingest, so completeness is a claim it can never truthfully make")
	}
	if strings.Contains(c.Summary(), "carries everything") {
		t.Errorf("summary claims full evaluation: %q", c.Summary())
	}
}

// The two planes are never conflated: an attacker who takes the tenant through Entra never touches an
// ARM role assignment, so a rich ARM snapshot says nothing about the directory.
func TestCoverAzure_DeclaresTheEntraPlaneOnEverySnapshot(t *testing.T) {
	for _, raw := range []azinventory.RawAzure{
		{},
		{SubscriptionID: "s", Principals: []azinventory.RawAzPrincipal{{ID: "sp:a"}},
			RoleAssignments: []azinventory.RawAzAssignment{{Role: "Owner", Principals: []string{"sp:a"}}},
			VMs:             []azinventory.RawAzVM{{ID: "vm"}}},
	} {
		note, ok := CoverAzure(raw).Notes["entra-directory"]
		if !ok {
			t.Fatal("the Entra plane was not declared — an empty Entra result would read as a clean directory")
		}
		if !strings.Contains(note, "SEPARATE authorization plane") {
			t.Errorf("the note does not keep the planes apart: %q", note)
		}
	}
}

// No role assignments means no escalation can be computed at all — which is what every Azure snapshot
// looked like before RawAzure gained the RBAC fields.
func TestCoverAzure_MissingRBACIsDeclared(t *testing.T) {
	c := CoverAzure(azinventory.RawAzure{
		SubscriptionID: "sub-1",
		Principals:     []azinventory.RawAzPrincipal{{ID: "sp:a", Admin: true}},
		VMs:            []azinventory.RawAzVM{{ID: "vm-1"}},
	})
	note, ok := c.Notes["privilege-escalation"]
	if !ok {
		t.Fatalf("no privilege-escalation note with zero role assignments: %v", c.Notes)
	}
	// The distinction that makes the note worth reading: `admin` is not an answer to "who can become
	// an admin".
	if !strings.Contains(note, "ALREADY") || !strings.Contains(note, "BECOME") {
		t.Errorf("the note does not distinguish who IS an admin from who can become one: %q", note)
	}
	if !strings.Contains(note, "role_assignments") {
		t.Errorf("the note does not name the field to populate: %q", note)
	}
}

// A custom role assigned without its definition is where the firm-allow rule costs recall, so the
// roles that went unanswered are named.
func TestCoverAzure_UnresolvedCustomRolesAreNamed(t *testing.T) {
	c := CoverAzure(azinventory.RawAzure{
		SubscriptionID: "sub-1",
		Principals:     []azinventory.RawAzPrincipal{{ID: "sp:a"}},
		VMs:            []azinventory.RawAzVM{{ID: "vm"}},
		RoleAssignments: []azinventory.RawAzAssignment{
			{Role: "Owner", Principals: []string{"sp:a"}},
			{Role: "custom-deployer", Principals: []string{"sp:b"}},
		},
	})
	note, ok := c.Notes["unresolved-roles"]
	if !ok {
		t.Fatalf("an assigned custom role with no definition was not declared: %v", c.Notes)
	}
	if !strings.Contains(note, "custom-deployer") {
		t.Errorf("the note does not name the role: %q", note)
	}
	if strings.Contains(note, "Owner") {
		t.Errorf("a built-in role was reported unresolved — azureiam understands them inline: %q", note)
	}
}
