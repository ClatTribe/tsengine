package gcpinventory

import (
	"testing"

	"github.com/ClatTribe/tsengine/internal/cloudgraph"
)

func gcpPrivescFor(inv cloudgraph.Inventory, member string) *cloudgraph.InvPrivesc {
	for i := range inv.Privescs {
		if inv.Privescs[i].Principal == member {
			return &inv.Privescs[i]
		}
	}
	return nil
}

// setIamPolicy on a project is the canonical GCP escalation: the holder can grant
// themselves owner. Before this, no production ingest produced such an edge at all.
func TestBuild_SetIamPolicyBecomesAnEscalationEdge(t *testing.T) {
	inv := Build(RawGCP{
		ProjectID: "p1",
		Bindings: []RawGCPBinding{{
			Role: "roles/custom.deployer", Members: []string{"user:dev@acme.com"},
		}},
		RoleDefs: map[string][]string{
			"roles/custom.deployer": {"resourcemanager.projects.setIamPolicy"},
		},
	})
	pe := gcpPrivescFor(inv, "user:dev@acme.com")
	if pe == nil {
		t.Fatal("a member who can rewrite the project IAM policy can make themselves owner")
	}
	if pe.Target != cloudgraph.AdminID || pe.Detail == "" {
		t.Fatalf("the edge must reach admin and name its technique: %+v", pe)
	}
}

// THE FLOOD GUARD, and the reason this file exists. gcpiam treats a role it has no
// definition for as POSSIBLY granting anything — correct for path-pruning, catastrophic
// for edge CREATION. Without the firm-allow rule, every principal holding any custom role
// would appear able to escalate, and the graph would fill with escalations inferred from
// a missing role definition rather than from a permission.
func TestBuild_UnknownRoleDoesNotManufactureAnEscalation(t *testing.T) {
	inv := Build(RawGCP{
		ProjectID: "p1",
		Bindings: []RawGCPBinding{
			{Role: "roles/custom.unknown-a", Members: []string{"user:a@acme.com"}},
			{Role: "roles/custom.unknown-b", Members: []string{"user:b@acme.com"}},
			{Role: "roles/custom.unknown-c", Members: []string{"serviceAccount:sa@p1.iam.gserviceaccount.com"}},
		},
		// No RoleDefs at all: we do not know what any of these grant.
	})
	if len(inv.Privescs) != 0 {
		t.Fatalf("an escalation inferred from a role definition we do not have is not evidence, "+
			"it is the absence of it: %+v", inv.Privescs)
	}
	// ...and the gap must be nameable rather than silent.
	unknown := UnknownRoles(RawGCP{Bindings: []RawGCPBinding{
		{Role: "roles/custom.unknown-a"}, {Role: "roles/viewer"},
	}})
	if len(unknown) != 1 || unknown[0] != "roles/custom.unknown-a" {
		t.Fatalf("unresolvable roles must be nameable, and basic roles are understood inline: %v", unknown)
	}
}

// A role we DO have, that does not grant escalation, yields nothing. The clean case stays clean.
func TestBuild_HarmlessKnownRoleYieldsNothing(t *testing.T) {
	inv := Build(RawGCP{
		ProjectID: "p1",
		Bindings:  []RawGCPBinding{{Role: "roles/custom.reader", Members: []string{"user:dev@acme.com"}}},
		RoleDefs:  map[string][]string{"roles/custom.reader": {"storage.objects.get"}},
	})
	if len(inv.Privescs) != 0 {
		t.Fatalf("reading an object is not escalation: %+v", inv.Privescs)
	}
	for _, r := range inv.Resources {
		if r.ID == cloudgraph.AdminID {
			t.Fatal("no escalation exists, so no admin node should be declared")
		}
	}
}

// A CONDITIONED binding is not a firm allow: the condition may not hold at runtime, so an edge
// asserted from it would claim more than the policy proves.
//
// This test used to require ZERO privescs, and that assertion was stronger than its own reasoning.
// Not asserting an escalation and not MENTIONING one are different things: dropping it silently is
// itself a claim, and a worse one, because the attack-path page then reports no route to admin for a
// principal who has a documented route the moment the condition holds. Conditions are what an
// attacker waits out or arranges.
//
// The edge is now emitted and MARKED — exactly what InvPrivesc.Condition was added for ("a
// config-possible escalation is never reported as confirmed") and what the AWS path has always
// done. The original intent is intact: nothing here is asserted as proven.
func TestBuild_ConditionedBindingIsReportedButNotAsserted(t *testing.T) {
	inv := Build(RawGCP{
		ProjectID: "p1",
		Bindings: []RawGCPBinding{{
			Role: "roles/custom.deployer", Members: []string{"user:dev@acme.com"},
			Condition: "request.time < timestamp('2026-01-01T00:00:00Z')",
		}},
		RoleDefs: map[string][]string{"roles/custom.deployer": {"resourcemanager.projects.setIamPolicy"}},
	})
	if len(inv.Privescs) != 1 {
		t.Fatalf("a condition-gated grant of setIamPolicy must be reported, got %d: %+v",
			len(inv.Privescs), inv.Privescs)
	}
	if inv.Privescs[0].Condition == "" {
		t.Fatal("...and must be marked config-possible rather than asserted as proven — an unmarked " +
			"edge here is the over-claim this test was originally written to prevent")
	}
}

// No bindings read at all: nothing claimed in either direction.
func TestBuild_NoBindingsProducesNoClaim(t *testing.T) {
	inv := Build(RawGCP{ProjectID: "p1", ServiceAccounts: []RawGCPSA{{Email: "sa@p1.iam.gserviceaccount.com"}}})
	if len(inv.Privescs) != 0 {
		t.Fatal("with no IAM policy read there is nothing to evaluate")
	}
	var present bool
	for _, r := range inv.Resources {
		if r.ID == "sa@p1.iam.gserviceaccount.com" {
			present = true
		}
	}
	if !present {
		t.Fatal("a service account whose bindings we did not read is still a service account")
	}
}

// roles/owner is understood inline by gcpiam, so an owner escalates without any RoleDefs.
func TestBuild_BasicOwnerRoleIsUnderstoodWithoutRoleDefs(t *testing.T) {
	inv := Build(RawGCP{
		ProjectID: "p1",
		Bindings:  []RawGCPBinding{{Role: "roles/owner", Members: []string{"user:boss@acme.com"}}},
	})
	if gcpPrivescFor(inv, "user:boss@acme.com") == nil {
		t.Fatal("roles/owner grants effectively everything and gcpiam knows it inline")
	}
}
