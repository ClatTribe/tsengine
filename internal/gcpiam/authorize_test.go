package gcpiam

import "testing"

func TestAuthorize_DirectBindingAllows(t *testing.T) {
	bucket := &Resource{Name: "bucket", Bindings: []Binding{
		{Role: "roles/storage.objectViewer", Members: []string{"serviceAccount:sa@p.iam.gserviceaccount.com"}},
	}}
	roles := map[string][]string{"roles/storage.objectViewer": {"storage.objects.get", "storage.objects.list"}}
	d, cond := Authorize(Request{Member: "serviceAccount:sa@p.iam.gserviceaccount.com", Permission: "storage.objects.get"}, PolicySet{Resource: bucket, Roles: roles})
	if d != Allow || cond {
		t.Fatalf("a direct binding granting the perm should firmly allow, got %s cond=%v", d, cond)
	}
}

func TestAuthorize_InheritedFromProject(t *testing.T) {
	project := &Resource{Name: "projects/p", Bindings: []Binding{
		{Role: "roles/editor", Members: []string{"user:dev@acme.com"}},
	}}
	bucket := &Resource{Name: "bucket", Parent: project}
	// editor is a known basic role granting (effectively) any write permission → inherited to the bucket.
	if d, _ := Authorize(Request{Member: "user:dev@acme.com", Permission: "storage.objects.create"}, PolicySet{Resource: bucket}); d != Allow {
		t.Fatalf("a project-level editor binding should inherit to the bucket, got %s", d)
	}
}

func TestAuthorize_NoBindingImplicitDeny(t *testing.T) {
	bucket := &Resource{Name: "bucket", Bindings: []Binding{
		{Role: "roles/viewer", Members: []string{"user:other@acme.com"}},
	}}
	// The requester isn't a member of any binding → deny-by-default (this is what lets the prune drop the edge).
	if d, _ := Authorize(Request{Member: "user:dev@acme.com", Permission: "storage.objects.get"}, PolicySet{Resource: bucket}); d != ImplicitDeny {
		t.Fatalf("no matching binding → implicit deny, got %s", d)
	}
}

func TestAuthorize_ViewerCannotWrite(t *testing.T) {
	bucket := &Resource{Name: "bucket", Bindings: []Binding{
		{Role: "roles/viewer", Members: []string{"user:dev@acme.com"}},
	}}
	// viewer (read-only) does NOT grant a create → definitive deny (a known role known not to grant).
	if d, _ := Authorize(Request{Member: "user:dev@acme.com", Permission: "storage.objects.create"}, PolicySet{Resource: bucket}); d != ImplicitDeny {
		t.Fatalf("viewer must not grant a write, got %s", d)
	}
	// but viewer DOES grant a read.
	if d, _ := Authorize(Request{Member: "user:dev@acme.com", Permission: "storage.objects.get"}, PolicySet{Resource: bucket}); d != Allow {
		t.Fatalf("viewer should grant a read, got %s", d)
	}
}

func TestAuthorize_AllUsersIsPublicAllow(t *testing.T) {
	bucket := &Resource{Name: "bucket", Bindings: []Binding{
		{Role: "roles/storage.objectViewer", Members: []string{"allUsers"}},
	}}
	roles := map[string][]string{"roles/storage.objectViewer": {"storage.objects.get"}}
	// The classic public-bucket finding: allUsers binding → anyone is allowed.
	if d, cond := Authorize(Request{Member: "user:anyone@evil.com", Permission: "storage.objects.get"}, PolicySet{Resource: bucket, Roles: roles}); d != Allow || cond {
		t.Fatalf("allUsers should firmly allow anyone, got %s cond=%v", d, cond)
	}
}

func TestAuthorize_DenyOverridesAllow(t *testing.T) {
	bucket := &Resource{Name: "bucket", Bindings: []Binding{
		{Role: "roles/owner", Members: []string{"user:dev@acme.com"}},
	}}
	denies := []DenyRule{{DeniedPermissions: []string{"storage.objects.delete"}, DeniedPrincipals: []string{"user:dev@acme.com"}}}
	if d, _ := Authorize(Request{Member: "user:dev@acme.com", Permission: "storage.objects.delete"}, PolicySet{Resource: bucket, Denies: denies}); d != ExplicitDeny {
		t.Fatalf("an IAM Deny must override even owner, got %s", d)
	}
	// an excepted principal escapes the deny (still allowed by owner).
	denies[0].ExceptionPrincipals = []string{"user:dev@acme.com"}
	if d, _ := Authorize(Request{Member: "user:dev@acme.com", Permission: "storage.objects.delete"}, PolicySet{Resource: bucket, Denies: denies}); d != Allow {
		t.Fatalf("an excepted principal should escape the deny, got %s", d)
	}
}

// Conservatism for pruning: an unresolved condition, an unknown custom role, and an unresolvable group all
// yield CONDITIONAL (a possible allow) — so the prune keeps the edge rather than dropping a maybe-real path.
func TestAuthorize_UncertaintyIsConditionalNotDeny(t *testing.T) {
	cases := []struct {
		name string
		ps   PolicySet
	}{
		{"condition-gated", PolicySet{Resource: &Resource{Bindings: []Binding{
			{Role: "roles/editor", Members: []string{"user:dev@acme.com"}, Condition: "request.time < ..."}}}}},
		{"unknown-custom-role", PolicySet{Resource: &Resource{Bindings: []Binding{
			{Role: "projects/p/roles/customMystery", Members: []string{"user:dev@acme.com"}}}}}},
		{"unresolvable-group", PolicySet{Resource: &Resource{Bindings: []Binding{
			{Role: "roles/owner", Members: []string{"group:eng@acme.com"}}}}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d, cond := Authorize(Request{Member: "user:dev@acme.com", Permission: "storage.objects.create"}, c.ps)
			if d != Allow || !cond {
				t.Errorf("%s should be a CONDITIONAL allow (keeps the edge), got %s cond=%v", c.name, d, cond)
			}
		})
	}
}

func TestAuthorize_DomainBinding(t *testing.T) {
	bucket := &Resource{Name: "bucket", Bindings: []Binding{
		{Role: "roles/viewer", Members: []string{"domain:acme.com"}},
	}}
	if d, cond := Authorize(Request{Member: "user:dev@acme.com", Permission: "storage.objects.get"}, PolicySet{Resource: bucket}); d != Allow || cond {
		t.Fatalf("a domain binding should firmly allow a member of that domain, got %s cond=%v", d, cond)
	}
	if d, _ := Authorize(Request{Member: "user:dev@other.com", Permission: "storage.objects.get"}, PolicySet{Resource: bucket}); d != ImplicitDeny {
		t.Fatalf("a different domain should not match, got %s", d)
	}
}
