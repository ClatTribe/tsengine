package cloudsearch

import (
	"testing"

	"github.com/ClatTribe/tsengine/internal/cloudgraph"
)

func ptr(b bool) *bool { return &b }

func sample() cloudgraph.Inventory {
	return cloudgraph.Inventory{
		AccountID: "123", Provider: "aws",
		Resources: []cloudgraph.InvResource{
			{ID: "s3-public", Kind: cloudgraph.KindResource, Type: "aws_s3_bucket", Name: "customer-data", Region: "us-east-1", Public: true, Sensitive: cloudgraph.SensHigh},
			{ID: "s3-private", Kind: cloudgraph.KindResource, Type: "aws_s3_bucket", Name: "build-artifacts", Region: "us-east-1"},
			{ID: "role-admin", Kind: cloudgraph.KindPrincipal, Type: "aws_iam_role", Name: "ops-admin", Privileged: true, Tags: map[string]string{"team": "platform"}},
			{ID: "ec2-web", Kind: cloudgraph.KindResource, Type: "aws_instance", Name: "web", Region: "eu-west-1", Public: true},
		},
		Grants:  []cloudgraph.InvGrant{{Principal: "role-admin", Resource: "s3-public"}},
		Reaches: []cloudgraph.InvReach{{From: "internet", To: "ec2-web"}},
	}
}

func TestSearch_PublicStorage(t *testing.T) {
	r := Search(sample(), Query{Type: "s3", Public: ptr(true)})
	if r.Total != 1 || r.Matches[0].ID != "s3-public" {
		t.Fatalf("want only the public bucket, got %+v", r)
	}
	// relationship JOIN: the public bucket is reached-by the admin role (a real grant edge).
	if len(r.Matches[0].ReachedBy) != 1 || r.Matches[0].ReachedBy[0] != "role-admin" {
		t.Errorf("public bucket should be reached-by role-admin, got %+v", r.Matches[0].ReachedBy)
	}
}

func TestSearch_FreeText(t *testing.T) {
	r := Search(sample(), Query{Text: "customer"})
	if r.Total != 1 || r.Matches[0].ID != "s3-public" {
		t.Fatalf("free-text on name should find customer-data, got %+v", r)
	}
}

func TestSearch_PrivilegedPrincipal(t *testing.T) {
	r := Search(sample(), Query{Privileged: ptr(true)})
	if r.Total != 1 || r.Matches[0].ID != "role-admin" {
		t.Fatalf("want the privileged role, got %+v", r)
	}
	// it reaches s3-public via the grant edge.
	if len(r.Matches[0].Reaches) != 1 || r.Matches[0].Reaches[0] != "s3-public" {
		t.Errorf("admin role should reach s3-public, got %+v", r.Matches[0].Reaches)
	}
}

func TestSearch_RegionAndSensitive(t *testing.T) {
	if r := Search(sample(), Query{Region: "us-east-1"}); r.Total != 2 {
		t.Errorf("us-east-1 has 2 resources, got %d", r.Total)
	}
	if r := Search(sample(), Query{Sensitive: ptr(true)}); r.Total != 1 || r.Matches[0].ID != "s3-public" {
		t.Errorf("only the sensitive bucket should match, got %+v", r)
	}
}

func TestSearch_TagAndType(t *testing.T) {
	if r := Search(sample(), Query{Tag: "team=platform"}); r.Total != 1 || r.Matches[0].ID != "role-admin" {
		t.Errorf("tag filter: %+v", r)
	}
	if r := Search(sample(), Query{Type: "s3"}); r.Total != 2 {
		t.Errorf("type substring s3 should match 2 buckets, got %d", r.Total)
	}
}

// Grounded §10: a query the inventory can't satisfy returns nothing — never invented.
func TestSearch_NoMatchAndEmpty(t *testing.T) {
	if r := Search(sample(), Query{Region: "ap-south-1"}); r.Total != 0 || len(r.Matches) != 0 {
		t.Errorf("no resource in ap-south-1, got %+v", r)
	}
	if r := Search(cloudgraph.Inventory{}, Query{}); r.Total != 0 {
		t.Errorf("empty inventory must yield nothing, got %+v", r)
	}
}

func TestSearch_LimitCountsTotal(t *testing.T) {
	r := Search(sample(), Query{Limit: 1})
	if r.Returned != 1 || r.Total != 4 {
		t.Fatalf("limit should cap Returned but not Total, got returned=%d total=%d", r.Returned, r.Total)
	}
}
