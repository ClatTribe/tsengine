package awsremediate

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// fakeS3 captures the PutPublicAccessBlock call so the test verifies it without AWS credentials.
type fakeS3 struct {
	in  *s3.PutPublicAccessBlockInput
	err error
}

func (f *fakeS3) PutPublicAccessBlock(_ context.Context, in *s3.PutPublicAccessBlockInput, _ ...func(*s3.Options)) (*s3.PutPublicAccessBlockOutput, error) {
	f.in = in
	if f.err != nil {
		return nil, f.err
	}
	return &s3.PutPublicAccessBlockOutput{}, nil
}

func TestS3Writer_BlocksPublicAccessAllFourFlags(t *testing.T) {
	fake := &fakeS3{}
	w := NewS3Writer("us-east-1", "", "")
	w.newClient = func(context.Context) (s3PublicAccessBlockAPI, error) { return fake, nil }

	if err := w.BlockS3PublicAccess(context.Background(), "acme-public-bucket"); err != nil {
		t.Fatalf("BlockS3PublicAccess: %v", err)
	}
	if fake.in == nil {
		t.Fatal("PutPublicAccessBlock was not called")
	}
	if fake.in.Bucket == nil || *fake.in.Bucket != "acme-public-bucket" {
		t.Errorf("bucket = %v", fake.in.Bucket)
	}
	cfg := fake.in.PublicAccessBlockConfiguration
	if cfg == nil {
		t.Fatal("no PublicAccessBlockConfiguration")
	}
	// all four flags must be ON — anything less leaves a public exposure path open
	for name, got := range map[string]*bool{
		"BlockPublicAcls":       cfg.BlockPublicAcls,
		"IgnorePublicAcls":      cfg.IgnorePublicAcls,
		"BlockPublicPolicy":     cfg.BlockPublicPolicy,
		"RestrictPublicBuckets": cfg.RestrictPublicBuckets,
	} {
		if got == nil || !*got {
			t.Errorf("%s must be true, got %v", name, got)
		}
	}
}

func TestS3Writer_EmptyBucketErrors(t *testing.T) {
	w := NewS3Writer("us-east-1", "", "")
	w.newClient = func(context.Context) (s3PublicAccessBlockAPI, error) { return &fakeS3{}, nil }
	if err := w.BlockS3PublicAccess(context.Background(), ""); err == nil {
		t.Error("empty bucket must error")
	}
}

func TestS3Writer_SurfacesAPIError(t *testing.T) {
	w := NewS3Writer("us-east-1", "", "")
	w.newClient = func(context.Context) (s3PublicAccessBlockAPI, error) {
		return &fakeS3{err: errors.New("AccessDenied")}, nil
	}
	err := w.BlockS3PublicAccess(context.Background(), "b")
	if err == nil || !errors.Is(err, err) { // surfaced, not swallowed
		t.Fatalf("API error must surface, got %v", err)
	}
}

// NewS3Writer must wire the real client factory (so a misconfigured construction can't silently
// no-op). We only assert it's set — invoking it would need real AWS config.
func TestNewS3Writer_WiresRealClientFactory(t *testing.T) {
	w := NewS3Writer("eu-west-1", "arn:aws:iam::111122223333:role/tsengine-write", "ext-1")
	if w.newClient == nil {
		t.Fatal("newClient factory not wired")
	}
	if w.Region != "eu-west-1" || w.RoleARN == "" || w.ExternalID != "ext-1" {
		t.Errorf("writer config wrong: %+v", w)
	}
}
