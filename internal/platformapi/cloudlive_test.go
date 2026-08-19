package platformapi

import (
	"context"
	"testing"

	"github.com/ClatTribe/tsengine/internal/connector/awsfetch"
	"github.com/ClatTribe/tsengine/internal/connector/awsinventory"
)

func liveFixture() awsfetch.Result {
	return awsfetch.Result{
		Sources: []string{"s3", "ec2"},
		Skipped: map[string]string{"iam": "the role cannot list IAM"},
		Raw: awsinventory.RawAWS{
			Buckets:   []awsinventory.RawBucket{{ARN: "arn:aws:s3:::crown", Name: "crown", Public: true, Sensitive: true}},
			Instances: []awsinventory.RawInstance{{ID: "i-web", PublicIP: true, ServicePort: 443}},
			Roles:     []awsinventory.RawIAMRole{{ARN: "arn:aws:iam::1:role/admin", Name: "admin", Admin: true}},
		},
	}
}

// An id on a surface that was SKIPPED must come back not-covered — never not-found. This is the
// whole safety property of the adapter: IAM was not read, so nothing may be concluded about a role,
// including that it still exists. Note the fixture DOES contain the role: even with the data
// present, an unread surface must refuse to answer, because in production it would be absent.
func TestLiveReader_SkippedSurfaceIsNotCovered(t *testing.T) {
	lr := newLiveReader(func(context.Context) (awsfetch.Result, error) { return liveFixture(), nil })

	got, err := lr.CheckLive(context.Background(), "arn:aws:iam::1:role/admin")
	if err != nil {
		t.Fatalf("CheckLive: %v", err)
	}
	if got.Covered {
		t.Fatal("IAM was skipped but the reader reported it as covered — the agent would treat its answer as fact")
	}
	if got.Found {
		t.Error("an unread surface must never report Found")
	}
	if got.Why == "" {
		t.Error("must carry why the surface was unread, so the agent can report the gap")
	}
}

// A covered surface answers for real: found resources carry their live flags, and a genuinely
// absent one reports found=false (a citable deletion).
func TestLiveReader_CoveredSurfaceAnswersForReal(t *testing.T) {
	lr := newLiveReader(func(context.Context) (awsfetch.Result, error) { return liveFixture(), nil })
	ctx := context.Background()

	b, _ := lr.CheckLive(ctx, "arn:aws:s3:::crown")
	if !b.Covered || !b.Found || !b.Public || !b.Sensitive {
		t.Errorf("bucket should be covered/found/public/sensitive, got %+v", b)
	}

	// EC2 instances carry an instance id, not an ARN — the agent holds the ARN form, so the
	// trailing-segment match is what keeps a live instance from reading as deleted.
	i, _ := lr.CheckLive(ctx, "arn:aws:ec2:us-east-1:1:instance/i-web")
	if !i.Covered || !i.Found || !i.Public {
		t.Errorf("instance should match on its trailing id and be public, got %+v", i)
	}

	gone, _ := lr.CheckLive(ctx, "arn:aws:s3:::deleted-bucket")
	if !gone.Covered || gone.Found {
		t.Errorf("s3 was read and this bucket is absent → covered but not found, got %+v", gone)
	}
}

// An id this reader cannot route is reported as not-covered, never as absent.
func TestLiveReader_UnknownIdShapeIsNotCovered(t *testing.T) {
	lr := newLiveReader(func(context.Context) (awsfetch.Result, error) { return liveFixture(), nil })
	got, _ := lr.CheckLive(context.Background(), "arn:aws:dynamodb:us-east-1:1:table/orders")
	if got.Covered || got.Found {
		t.Errorf("an unroutable id must be not-covered, got %+v", got)
	}
}

// The account is read ONCE per investigation however many questions the agent asks — the property
// that keeps the live capability affordable enough to leave enabled.
func TestLiveReader_ReadsTheAccountOnce(t *testing.T) {
	calls := 0
	lr := newLiveReader(func(context.Context) (awsfetch.Result, error) {
		calls++
		return liveFixture(), nil
	})
	ctx := context.Background()
	for i := 0; i < 5; i++ {
		if _, err := lr.CheckLive(ctx, "arn:aws:s3:::crown"); err != nil {
			t.Fatalf("CheckLive: %v", err)
		}
	}
	if calls != 1 {
		t.Errorf("account read %d times for 5 questions, want 1 — per-question fetching would be slow and rate-limited", calls)
	}
}
