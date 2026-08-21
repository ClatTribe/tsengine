package awsfetch

import (
	"context"
	"strings"
	"testing"
)

// The most reassuring wrong answer this product could give is "there is no way to become
// admin in your account" when the truth is that nobody read the policies. Listing
// principals without their policy documents produces exactly zero escalation edges, so
// the omission has to be stated.
func TestCoverage_NamesUnreadPoliciesSoEmptyDoesNotReadAsSafe(t *testing.T) {
	res, _ := Fetcher{
		AccountID:  "1234",
		Buckets:    fakeLister{out: []Bucket{{Name: "b"}}},
		Principals: fakeIAM{out: []Principal{{ARN: "arn:aws:iam::1:role/app", Name: "app", Role: true}}},
	}.Fetch(context.Background())

	if _, said := res.Skipped["iam-policies"]; !said {
		t.Fatal("principals were listed with no policy documents — that gap must be declared")
	}
	cov := res.Coverage()
	if !strings.Contains(cov, "iam-policies") {
		t.Fatalf("the coverage line is where a reader looks; it must name the gap: %q", cov)
	}
	// The inventory really does contain no escalation, which is why silence would mislead.
	if len(res.Raw.Roles) != 1 {
		t.Fatalf("the role itself was read and must still be present: %+v", res.Raw.Roles)
	}
}

// Once policies ARE read, the caveat must disappear — a permanent warning is ignored as
// reliably as a missing one.
func TestCoverage_StopsNamingPoliciesOnceTheyAreRead(t *testing.T) {
	res, _ := Fetcher{
		AccountID: "1234",
		Buckets:   fakeLister{out: []Bucket{{Name: "b"}}},
		Principals: fakeIAM{out: []Principal{{
			ARN: "arn:aws:iam::1:role/app", Name: "app", Role: true,
			Policies: []string{`{"Statement":[{"Effect":"Allow","Action":["s3:GetObject"],"Resource":"*"}]}`},
		}}},
	}.Fetch(context.Background())

	if _, said := res.Skipped["iam-policies"]; said {
		t.Fatalf("policies were read; the caveat must not persist: %v", res.Skipped)
	}
}

// The policy documents must actually reach the inventory builder, or the whole path is
// decorative.
func TestFetch_PolicyDocumentsReachTheInventory(t *testing.T) {
	pol := `{"Statement":[{"Effect":"Allow","Action":["iam:CreatePolicyVersion"],"Resource":"*"}]}`
	bnd := `{"Statement":[{"Effect":"Allow","Action":["s3:Get*"],"Resource":"*"}]}`
	res, _ := Fetcher{
		AccountID: "1234",
		Buckets:   fakeLister{out: []Bucket{{Name: "b"}}},
		Principals: fakeIAM{out: []Principal{{
			ARN: "arn:aws:iam::1:role/app", Name: "app", Role: true,
			Policies: []string{pol}, Boundary: bnd,
		}}},
	}.Fetch(context.Background())

	if len(res.Raw.Roles) != 1 {
		t.Fatalf("want one role, got %+v", res.Raw.Roles)
	}
	r := res.Raw.Roles[0]
	if len(r.PoliciesJSON) != 1 || r.PoliciesJSON[0] != pol {
		t.Fatalf("policy documents did not reach the raw inventory: %+v", r.PoliciesJSON)
	}
	if r.BoundaryJSON != bnd {
		t.Fatalf("the permission boundary did not reach the raw inventory: %q", r.BoundaryJSON)
	}
}
