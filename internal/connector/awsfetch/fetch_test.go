package awsfetch

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
)

// A fetched inventory that cannot say what it covered is more dangerous than no inventory at all: it
// LOOKS live, and cloudgraph builds attack paths from principals and network reach. An inventory with
// buckets and no IAM cannot form a path, so an agent reasoning over it finds none — and reports an
// account as clean when nothing about its identity layer was read.

type fakeLister struct {
	out []Bucket
	err error
}

func (f fakeLister) ListBuckets(context.Context) ([]Bucket, error) { return f.out, f.err }

func TestFetch_RefusesRatherThanReturnAnEmptyAccount(t *testing.T) {
	_, err := Fetcher{AccountID: "1234"}.Fetch(context.Background())
	if err == nil {
		t.Fatal("a fetcher with no AWS access returned an inventory — an empty one is " +
			"indistinguishable from an account with nothing in it, which is a clean bill of health " +
			"nobody earned")
	}
	if !strings.Contains(err.Error(), "no AWS access") {
		t.Errorf("the refusal does not say why: %v", err)
	}
}

func TestFetch_ReportsWhatItActuallyRead(t *testing.T) {
	res, err := Fetcher{
		AccountID: "1234",
		Buckets:   fakeLister{out: []Bucket{{Name: "logs", Public: true}, {Name: "assets"}}},
	}.Fetch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Raw.Buckets) != 2 {
		t.Fatalf("mapped %d buckets, want 2", len(res.Raw.Buckets))
	}
	if !res.Covers("s3") {
		t.Error("s3 was read but not reported as covered")
	}
	// The surfaces it did NOT read must be named, or their absence reads as "the account has none".
	for _, unread := range []string{"iam", "ec2"} {
		if _, ok := res.Skipped[unread]; !ok {
			t.Errorf("%q was never read and is not listed as skipped — an agent would treat its "+
				"absence as an account with no %s", unread, unread)
		}
		if res.Covers(unread) {
			t.Errorf("%q reported as covered when it was not read", unread)
		}
	}
}

// The coverage line is what a caller shows next to any conclusion. It must never be silent.
func TestCoverage_IsNeverSilentAboutWhatIsMissing(t *testing.T) {
	res, _ := Fetcher{
		AccountID: "1234",
		Buckets:   fakeLister{out: []Bucket{{Name: "b"}}},
	}.Fetch(context.Background())

	cov := res.Coverage()
	if !strings.Contains(cov, "s3") {
		t.Errorf("coverage does not say what was read: %q", cov)
	}
	if !strings.Contains(cov, "iam") || !strings.Contains(cov, "ec2") {
		t.Errorf("coverage does not name the unread surfaces: %q", cov)
	}
	if !strings.Contains(cov, "attack paths") {
		t.Errorf("coverage does not say what the gap COSTS, only that it exists: %q", cov)
	}

	// And with nothing read at all, it must say so rather than return an empty string.
	if got := (Result{}).Coverage(); got == "" || !strings.Contains(got, "states nothing") {
		t.Errorf("an empty result's coverage = %q; silence would let it pass for a whole picture", got)
	}
}

// One failing surface must not fail the whole fetch — but it must be recorded, not swallowed.
func TestFetch_RecordsAFailedSurfaceRatherThanHidingIt(t *testing.T) {
	res, err := Fetcher{
		AccountID: "1234",
		Buckets:   fakeLister{err: errors.New("AccessDenied: s3:ListAllMyBuckets")},
	}.Fetch(context.Background())

	// Every surface failed here, so the fetch itself fails — there is nothing honest to return.
	if err == nil {
		t.Fatal("a fetch where every surface failed returned success")
	}
	if got := res.Skipped["s3"]; !strings.Contains(got, "AccessDenied") {
		t.Errorf("the S3 failure was not recorded with its cause: %q", got)
	}
	if res.Covers("s3") {
		t.Error("a surface that failed to read was reported as covered")
	}
}

func TestBlocksPublic_RequiresAllFourFlags(t *testing.T) {
	yes, no := true, false
	if blocksPublic(nil) {
		t.Error("a nil public-access-block reported as blocking")
	}
	// Three of four still leaves a way in — AWS treats the flags independently.
	if blocksPublic(pab(&yes, &yes, &yes, &no)) {
		t.Error("three-of-four flags reported as blocking public access")
	}
	if !blocksPublic(pab(&yes, &yes, &yes, &yes)) {
		t.Error("all four flags set did not report as blocking")
	}
	// A nil flag is not a set flag.
	if blocksPublic(pab(&yes, nil, &yes, &yes)) {
		t.Error("an unset flag was treated as set")
	}
}

// pab builds a GetPublicAccessBlockOutput for the flag table above.
func pab(acls, policy, ignore, restrict *bool) *s3.GetPublicAccessBlockOutput {
	return &s3.GetPublicAccessBlockOutput{
		PublicAccessBlockConfiguration: &s3types.PublicAccessBlockConfiguration{
			BlockPublicAcls: acls, BlockPublicPolicy: policy,
			IgnorePublicAcls: ignore, RestrictPublicBuckets: restrict,
		},
	}
}
