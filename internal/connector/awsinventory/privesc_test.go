package awsinventory

import (
	"testing"

	"github.com/ClatTribe/tsengine/internal/cloudgraph"
)

const escalatingPolicy = `{"Statement":[{"Effect":"Allow","Action":["iam:CreatePolicyVersion"],"Resource":"*"}]}`
const readOnlyBoundary = `{"Statement":[{"Effect":"Allow","Action":["s3:Get*"],"Resource":"*"}]}`
const openBoundary = `{"Statement":[{"Effect":"Allow","Action":["*"],"Resource":"*"}]}`

func privescFor(inv cloudgraph.Inventory, principal string) *cloudgraph.InvPrivesc {
	for i := range inv.Privescs {
		if inv.Privescs[i].Principal == principal {
			return &inv.Privescs[i]
		}
	}
	return nil
}

// The capability that did not exist on real accounts: a policy-DERIVED escalation edge.
// Before this, a principal was marked Privileged from an `Admin` boolean, which answers
// "is this already admin" and never "can this BECOME admin" — the attack path itself.
func TestBuild_PolicyDerivedPrivescEdgeIsProduced(t *testing.T) {
	inv := Build(RawAWS{AccountID: "1", Roles: []RawIAMRole{{
		ARN: "arn:aws:iam::1:role/app", Name: "app", PoliciesJSON: []string{escalatingPolicy},
	}}})

	pe := privescFor(inv, "arn:aws:iam::1:role/app")
	if pe == nil {
		t.Fatal("a role that can rewrite its own policy can become admin — that edge must exist")
	}
	if pe.Target != cloudgraph.AdminID {
		t.Fatalf("escalation targets the synthetic admin node, got %q", pe.Target)
	}
	if pe.Detail == "" {
		t.Fatal("the edge must name the technique, or a reader cannot check it")
	}
	// The admin node has to be declared, or the edge dangles.
	var declared bool
	for _, r := range inv.Resources {
		if r.ID == cloudgraph.AdminID && r.Privileged {
			declared = true
		}
	}
	if !declared {
		t.Fatal("the admin node must be declared alongside the edge that reaches it")
	}
}

// THE FIX, at the ingest layer. AWS computes effective = attached ∧ boundary.
func TestBuild_PermissionBoundaryBlocksTheEdge(t *testing.T) {
	inv := Build(RawAWS{AccountID: "1", Roles: []RawIAMRole{{
		ARN: "arn:aws:iam::1:role/app", Name: "app",
		PoliciesJSON: []string{escalatingPolicy}, BoundaryJSON: readOnlyBoundary,
	}}})

	if pe := privescFor(inv, "arn:aws:iam::1:role/app"); pe != nil {
		t.Fatalf("the boundary permits only s3:Get* — this escalation is blocked, and a false "+
			"path to admin sends someone to sever a route that was never open: %+v", pe)
	}
	for _, r := range inv.Resources {
		if r.ID == cloudgraph.AdminID {
			t.Fatal("nothing can escalate, so no admin node should be declared")
		}
	}
}

func TestBuild_PermissiveBoundaryKeepsTheEdge(t *testing.T) {
	inv := Build(RawAWS{AccountID: "1", Roles: []RawIAMRole{{
		ARN: "arn:aws:iam::1:role/app", PoliciesJSON: []string{escalatingPolicy}, BoundaryJSON: openBoundary,
	}}})
	if privescFor(inv, "arn:aws:iam::1:role/app") == nil {
		t.Fatal("a boundary permitting everything does not block the escalation — the edge is real")
	}
}

// "We did not read the policies" and "there is no escalation" are different facts.
func TestBuild_NoPolicyDocumentsProducesNoEdgeAndNoClaim(t *testing.T) {
	inv := Build(RawAWS{AccountID: "1", Roles: []RawIAMRole{{
		ARN: "arn:aws:iam::1:role/app", Name: "app", Admin: false,
	}}})
	if len(inv.Privescs) != 0 {
		t.Fatal("with no policy documents there is nothing to evaluate — inventing an edge would be worse than silence")
	}
	// ...and the role must still be in the graph, because it exists.
	var present bool
	for _, r := range inv.Resources {
		if r.ID == "arn:aws:iam::1:role/app" {
			present = true
		}
	}
	if !present {
		t.Fatal("a principal whose policies we could not read is still a principal")
	}
}

// An unparseable boundary must not be read as denying everything, or one malformed
// document silently erases every escalation in the account.
func TestBuild_UnparseableBoundaryDoesNotSuppressTheEdge(t *testing.T) {
	inv := Build(RawAWS{AccountID: "1", Roles: []RawIAMRole{{
		ARN: "arn:aws:iam::1:role/app", PoliciesJSON: []string{escalatingPolicy}, BoundaryJSON: "<<<broken",
	}}})
	if privescFor(inv, "arn:aws:iam::1:role/app") == nil {
		t.Fatal("a boundary we could not parse is not a boundary that denies everything")
	}
}

// A non-escalating policy yields nothing — the clean case must stay clean.
func TestBuild_HarmlessPolicyYieldsNoEdge(t *testing.T) {
	inv := Build(RawAWS{AccountID: "1", Roles: []RawIAMRole{{
		ARN:          "arn:aws:iam::1:role/app",
		PoliciesJSON: []string{`{"Statement":[{"Effect":"Allow","Action":["s3:GetObject"],"Resource":"*"}]}`},
	}}})
	if len(inv.Privescs) != 0 {
		t.Fatalf("reading an object is not privilege escalation: %+v", inv.Privescs)
	}
}

// Users escalate too, and were equally invisible.
func TestBuild_UsersGetPrivescEdgesAsWellAsRoles(t *testing.T) {
	inv := Build(RawAWS{AccountID: "1", Users: []RawIAMUser{{
		ARN: "arn:aws:iam::1:user/dev", Name: "dev", PoliciesJSON: []string{escalatingPolicy},
	}}})
	if privescFor(inv, "arn:aws:iam::1:user/dev") == nil {
		t.Fatal("an IAM user with a self-rewriting policy escalates exactly like a role")
	}
}
