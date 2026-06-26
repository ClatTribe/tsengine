package azureiam

import "testing"

func TestAuthorize_AssignmentAndInheritance(t *testing.T) {
	sub := &Scope{Name: "sub", Assignments: []Assignment{{Role: "Reader", Principals: []string{"user:dev@acme.com"}}}}
	rg := &Scope{Name: "rg", Parent: sub}
	// Reader assigned at the subscription is inherited to the resource group → a read is allowed.
	if d, cond := Authorize(Request{Principal: "user:dev@acme.com", Action: "Microsoft.Storage/storageAccounts/read"}, PolicySet{Scope: rg}); d != Allow || cond {
		t.Fatalf("inherited Reader should firmly allow a read, got %s cond=%v", d, cond)
	}
	// Reader does NOT grant a write → definitive deny (lets the prune drop the edge).
	if d, _ := Authorize(Request{Principal: "user:dev@acme.com", Action: "Microsoft.Storage/storageAccounts/write"}, PolicySet{Scope: rg}); d != ImplicitDeny {
		t.Fatalf("Reader must not grant a write, got %s", d)
	}
}

func TestAuthorize_ContributorExcludesAuthorizationWrites(t *testing.T) {
	sc := &Scope{Assignments: []Assignment{{Role: "Contributor", Principals: []string{"sp:app@acme"}}}}
	// Contributor grants a storage write...
	if d, _ := Authorize(Request{Principal: "sp:app@acme", Action: "Microsoft.Storage/storageAccounts/write"}, PolicySet{Scope: sc}); d != Allow {
		t.Fatalf("Contributor should grant a storage write, got %s", d)
	}
	// ...but NOT a role-assignment write (the NotActions exclusion that stops self-escalation).
	if d, _ := Authorize(Request{Principal: "sp:app@acme", Action: "Microsoft.Authorization/roleAssignments/write"}, PolicySet{Scope: sc}); d != ImplicitDeny {
		t.Fatalf("Contributor must NOT grant role-assignment write (privesc guard), got %s", d)
	}
	// Owner does grant it.
	owner := &Scope{Assignments: []Assignment{{Role: "Owner", Principals: []string{"sp:app@acme"}}}}
	if d, _ := Authorize(Request{Principal: "sp:app@acme", Action: "Microsoft.Authorization/roleAssignments/write"}, PolicySet{Scope: owner}); d != Allow {
		t.Fatalf("Owner should grant role-assignment write, got %s", d)
	}
}

func TestAuthorize_CustomRoleActionsAndNotActions(t *testing.T) {
	roles := map[string]RoleDef{"custom": {Actions: []string{"Microsoft.Storage/*"}, NotActions: []string{"Microsoft.Storage/storageAccounts/delete"}}}
	sc := &Scope{Assignments: []Assignment{{Role: "custom", Principals: []string{"user:x@acme.com"}}}}
	if d, _ := Authorize(Request{Principal: "user:x@acme.com", Action: "Microsoft.Storage/storageAccounts/read"}, PolicySet{Scope: sc, Roles: roles}); d != Allow {
		t.Fatalf("custom role should grant a matching action, got %s", d)
	}
	if d, _ := Authorize(Request{Principal: "user:x@acme.com", Action: "Microsoft.Storage/storageAccounts/delete"}, PolicySet{Scope: sc, Roles: roles}); d != ImplicitDeny {
		t.Fatalf("a NotActions exclusion must block the action, got %s", d)
	}
}

func TestAuthorize_DenyAssignmentOverrides(t *testing.T) {
	sc := &Scope{Assignments: []Assignment{{Role: "Owner", Principals: []string{"user:x@acme.com"}}}}
	denies := []DenyAssignment{{Actions: []string{"Microsoft.Storage/storageAccounts/delete"}, Principals: []string{"user:x@acme.com"}}}
	if d, _ := Authorize(Request{Principal: "user:x@acme.com", Action: "Microsoft.Storage/storageAccounts/delete"}, PolicySet{Scope: sc, Denies: denies}); d != ExplicitDeny {
		t.Fatalf("a deny assignment must override even Owner, got %s", d)
	}
}

func TestAuthorize_UncertaintyIsConditional(t *testing.T) {
	cases := map[string]PolicySet{
		"condition": {Scope: &Scope{Assignments: []Assignment{{Role: "Owner", Principals: []string{"user:x@acme.com"}, Condition: "@Resource[...]"}}}},
		"unknown-role": {Scope: &Scope{Assignments: []Assignment{{Role: "SomeCustomRole", Principals: []string{"user:x@acme.com"}}}}},
		"group": {Scope: &Scope{Assignments: []Assignment{{Role: "Owner", Principals: []string{"group:eng@acme.com"}}}}},
	}
	for name, ps := range cases {
		t.Run(name, func(t *testing.T) {
			if d, cond := Authorize(Request{Principal: "user:x@acme.com", Action: "Microsoft.Storage/storageAccounts/write"}, ps); d != Allow || !cond {
				t.Errorf("%s should be a conditional allow (keeps the edge), got %s cond=%v", name, d, cond)
			}
		})
	}
}
