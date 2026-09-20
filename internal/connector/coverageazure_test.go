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
func TestCoverAzure_ARMOnlySnapshotStillFlagsTheUnreadEntraPlane(t *testing.T) {
	// A rich ARM snapshot that carries NO Entra fields left the identity plane unread, so coverage
	// is not complete and the Entra note fires. (Before D2a wired the plane this note was
	// unconditional; now it is the honest "not evaluated" signal, fired only when Entra is absent.)
	raw := azinventory.RawAzure{
		SubscriptionID:  "sub-1",
		Principals:      []azinventory.RawAzPrincipal{{ID: "sp:a", Name: "a"}},
		VMs:             []azinventory.RawAzVM{{ID: "vm-1"}},
		Storage:         []azinventory.RawAzStorage{{Name: "st1"}},
		RoleAssignments: []azinventory.RawAzAssignment{{Role: "Owner", Principals: []string{"sp:a"}}},
	}
	c := CoverAzure(raw)
	if _, ok := c.Notes["entra-directory"]; !ok {
		t.Fatal("an ARM-only snapshot carries no Entra holdings, so the plane was unread — the note must fire")
	}
	if c.Complete() {
		t.Fatal("an unread plane cannot be complete coverage")
	}
	if strings.Contains(c.Summary(), "carries everything") {
		t.Errorf("summary claims full evaluation: %q", c.Summary())
	}
}

// The Entra note is the honest not-evaluated signal (§10): it fires when no principal carries any
// Entra holding (the plane went unread — an empty result must not read as a clean directory), and is
// ABSENT when the snapshot DID carry Entra fields (the plane was evaluated). Before D2a wired the
// plane, the note was unconditional — correct then, and stale the moment the ingest could read Entra.
func TestCoverAzure_EntraNoteFiresOnlyWhenThePlaneIsUnread(t *testing.T) {
	// No Entra fields → unread → note present, keeping the planes apart.
	for _, raw := range []azinventory.RawAzure{
		{},
		{SubscriptionID: "s", Principals: []azinventory.RawAzPrincipal{{ID: "sp:a"}},
			RoleAssignments: []azinventory.RawAzAssignment{{Role: "Owner", Principals: []string{"sp:a"}}},
			VMs:             []azinventory.RawAzVM{{ID: "vm"}}},
	} {
		note, ok := CoverAzure(raw).Notes["entra-directory"]
		if !ok {
			t.Fatal("an unread Entra plane must be declared — an empty Entra result would read as a clean directory")
		}
		if !strings.Contains(note, "separate authorization plane") {
			t.Errorf("the note does not keep the planes apart: %q", note)
		}
	}

	// A snapshot that DID carry Entra holdings evaluated the plane, so the not-evaluated note must be
	// ABSENT — otherwise a customer who supplied the data is told it was ignored.
	withEntra := azinventory.RawAzure{
		SubscriptionID: "s",
		Principals: []azinventory.RawAzPrincipal{
			{ID: "sp:a", GraphPermissions: []string{"Application.ReadWrite.All"}},
		},
	}
	if _, ok := CoverAzure(withEntra).Notes["entra-directory"]; ok {
		t.Error("the Entra plane WAS evaluated (graph_permissions supplied) — the not-evaluated note must not fire")
	}
	// directory_roles and owns count as holdings too.
	for _, raw := range []azinventory.RawAzure{
		{Principals: []azinventory.RawAzPrincipal{{ID: "u", DirectoryRoles: []string{"Global Administrator"}}}},
		{Principals: []azinventory.RawAzPrincipal{{ID: "u", Owns: []string{"sp:x"}}}},
	} {
		if _, ok := CoverAzure(raw).Notes["entra-directory"]; ok {
			t.Error("any Entra holding means the plane was read — the note must not fire")
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
