package gcpremediate

import (
	"context"
	"errors"
	"testing"
)

type fakeGCS struct {
	bucket string
	closed bool
	err    error
}

func (f *fakeGCS) EnforcePublicAccessPrevention(_ context.Context, bucket string) error {
	f.bucket = bucket
	return f.err
}
func (f *fakeGCS) Close() error { f.closed = true; return nil }

func TestGCSWriter_EnforcesPublicAccessPrevention(t *testing.T) {
	fake := &fakeGCS{}
	w := NewGCSWriter("")
	w.newClient = func(context.Context, string) (gcsBucketAPI, error) { return fake, nil }

	if err := w.EnforceBucketPublicAccessPrevention(context.Background(), "acme-proj", "acme-public-bucket"); err != nil {
		t.Fatalf("EnforceBucketPublicAccessPrevention: %v", err)
	}
	if fake.bucket != "acme-public-bucket" {
		t.Errorf("bucket = %q", fake.bucket)
	}
	if !fake.closed {
		t.Error("client must be closed (no leak)")
	}
}

func TestGCSWriter_EmptyBucketErrors(t *testing.T) {
	w := NewGCSWriter("")
	w.newClient = func(context.Context, string) (gcsBucketAPI, error) { return &fakeGCS{}, nil }
	if err := w.EnforceBucketPublicAccessPrevention(context.Background(), "p", ""); err == nil {
		t.Error("empty bucket must error")
	}
}

func TestGCSWriter_SurfacesAPIError(t *testing.T) {
	w := NewGCSWriter("")
	w.newClient = func(context.Context, string) (gcsBucketAPI, error) {
		return &fakeGCS{err: errors.New("PERMISSION_DENIED")}, nil
	}
	err := w.EnforceBucketPublicAccessPrevention(context.Background(), "p", "b")
	if err == nil {
		t.Fatal("API error must surface")
	}
}

func TestNewGCSWriter_WiresRealClientFactory(t *testing.T) {
	w := NewGCSWriter("writer@acme.iam.gserviceaccount.com")
	if w.newClient == nil {
		t.Fatal("newClient factory not wired")
	}
	if w.ImpersonateSA == "" {
		t.Error("ImpersonateSA not set")
	}
}
