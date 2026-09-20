package azinventory

import (
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/internal/cloudgraph"
)

// THE HOLE THIS CLOSES. §10 claims privesc-edge generation is symmetric across AWS+GCP+Azure, and it
// was — of the EVALUATORS. azureiam.DetectPrivesc existed and was tested; RawAzure had no field for a
// role assignment, so nothing could call it with real data and every Azure snapshot ever posted
// produced zero escalation edges by construction rather than by evidence.
func TestDerivePrivesc_AnOwnerAssignmentBecomesAnEscalationEdge(t *testing.T) {
	inv := Build(RawAzure{
		SubscriptionID: "sub-1",
		Principals:     []RawAzPrincipal{{ID: "sp:deployer", Name: "deployer"}},
		RoleAssignments: []RawAzAssignment{{
			Role: "Owner", Principals: []string{"sp:deployer"},
		}},
	})
	if len(inv.Privescs) != 1 {
		t.Fatalf("an Owner assignment produced %d privesc edges, want 1: %+v", len(inv.Privescs), inv.Privescs)
	}
	p := inv.Privescs[0]
	if p.Principal != "sp:deployer" || p.Target != cloudgraph.AdminID {
		t.Errorf("edge = %s → %s", p.Principal, p.Target)
	}
	if p.Condition != "" {
		t.Errorf("an unconditional Owner assignment was reported as config-possible: %q", p.Condition)
	}
	if p.Detail == "" {
		t.Error("the edge names no technique, so a reader cannot check the claim")
	}
	// The admin node has to exist or the edge points at nothing.
	var hasAdmin bool
	for _, r := range inv.Resources {
		if r.ID == cloudgraph.AdminID {
			hasAdmin = true
		}
	}
	if !hasAdmin {
		t.Error("no effective-admin node was added, so the escalation edge has no target")
	}
}

// A grant that is REAL but condition-gated must be reported WITH the caveat, not dropped. Measured on
// GCP before its equivalent fix: a member who could escalate today produced zero edges because the
// binding carried a condition, and the attack-path page said there was no route to admin.
func TestDerivePrivesc_AConditionGatedGrantIsReportedAsConfigPossible(t *testing.T) {
	inv := Build(RawAzure{
		SubscriptionID: "sub-1",
		RoleAssignments: []RawAzAssignment{{
			Role: "Owner", Principals: []string{"sp:deployer"},
			Condition: "@Resource[Microsoft.Storage/...] StringEquals 'x'",
		}},
	})
	if len(inv.Privescs) != 1 {
		t.Fatalf("a condition-gated escalation vanished: %+v", inv.Privescs)
	}
	if !strings.Contains(inv.Privescs[0].Condition, "config-possible") {
		t.Errorf("a gated escalation was reported as definite: %q", inv.Privescs[0].Condition)
	}
}

// THE FIRM-ALLOW RULE. azureiam treats a role it lacks the definition for as possibly granting
// anything — right for pruning an edge you cannot disprove, wrong for creating one. Without this a
// single unresolved custom role makes every principal holding it satisfy every technique.
func TestDerivePrivesc_AnUnknownCustomRoleDoesNotManufactureAnEscalation(t *testing.T) {
	inv := Build(RawAzure{
		SubscriptionID:  "sub-1",
		RoleAssignments: []RawAzAssignment{{Role: "custom-mystery-role", Principals: []string{"sp:app"}}},
	})
	for _, p := range inv.Privescs {
		if p.Condition == "" {
			t.Errorf("an unknown custom role produced a DEFINITE escalation: %+v", p)
		}
	}
	// And the caller is told which role went unanswered, rather than left with a silent gap.
	unknown := UnknownRoles(RawAzure{
		RoleAssignments: []RawAzAssignment{{Role: "custom-mystery-role"}, {Role: "Owner"}},
	})
	if len(unknown) != 1 || unknown[0] != "custom-mystery-role" {
		t.Errorf("UnknownRoles = %v; built-ins are understood inline and must not appear", unknown)
	}
}

// A read-only subscription yields nothing. The mirror matters as much as the detection: a collector
// that reported an escalation for Reader would be worse than one that reported none.
func TestDerivePrivesc_AReaderAssignmentEscalatesNothing(t *testing.T) {
	inv := Build(RawAzure{
		SubscriptionID:  "sub-1",
		RoleAssignments: []RawAzAssignment{{Role: "Reader", Principals: []string{"sp:viewer"}}},
	})
	if len(inv.Privescs) != 0 {
		t.Fatalf("Reader produced escalation edges: %+v", inv.Privescs)
	}
}

// No RBAC in the snapshot means nothing evaluated and nothing claimed — the coverage layer is what
// says so; Build must not invent an edge or an admin node from an absence.
func TestDerivePrivesc_NoRBACAssertsNothing(t *testing.T) {
	inv := Build(RawAzure{SubscriptionID: "sub-1", Principals: []RawAzPrincipal{{ID: "sp:a"}}})
	if len(inv.Privescs) != 0 {
		t.Fatalf("privescs invented with no role assignments: %+v", inv.Privescs)
	}
	for _, r := range inv.Resources {
		if r.ID == cloudgraph.AdminID {
			t.Error("an effective-admin node was added with no RBAC to justify it")
		}
	}
}

// A deny assignment is the policy working. It must actually suppress the escalation, or the
// evaluator's deny handling is decorative.
func TestDerivePrivesc_ADenyAssignmentSuppressesTheEscalation(t *testing.T) {
	raw := RawAzure{
		SubscriptionID:  "sub-1",
		RoleAssignments: []RawAzAssignment{{Role: "Owner", Principals: []string{"sp:deployer"}}},
		DenyAssignments: []RawAzDenyAssignment{{
			Actions: []string{"*"}, Principals: []string{"sp:deployer"},
		}},
	}
	if inv := Build(raw); len(inv.Privescs) != 0 {
		t.Fatalf("a deny assignment did not suppress the escalation: %+v", inv.Privescs)
	}
}
