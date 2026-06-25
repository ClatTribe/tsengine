// Package gcpremediate is the LIVE GCP write path for cloud remediation — the SDK-backed
// implementation of connector.GCPWriter that connector.GCP.Apply routes to (it returns an honest
// "no live write path" stub when no writer is wired). It is a SEPARATE package so the Google Cloud
// SDK stays out of the core connector package (which the read-only OAuth connectors share and
// unit-test without any SDK), mirroring internal/connector/awsremediate.
//
// Today it implements the GCS analogue of S3 Block Public Access: enforcing Public Access
// Prevention on a bucket (no object/bucket can be made public). Reached ONLY after the HITL gate
// (§18.2 inv. 3). Writes need real WRITE credentials — the writer impersonates a scoped write
// service account in the customer project (distinct from the read-only Security Reviewer grant).
package gcpremediate

import (
	"context"
	"fmt"

	"cloud.google.com/go/storage"
	"google.golang.org/api/impersonate"
	"google.golang.org/api/option"
)

// gcsBucketAPI is the minimal GCS surface the writer uses — a test injects a fake (no GCP creds).
type gcsBucketAPI interface {
	// EnforcePublicAccessPrevention sets the bucket's Public Access Prevention to "enforced".
	EnforcePublicAccessPrevention(ctx context.Context, bucket string) error
	Close() error
}

// GCSWriter implements connector.GCPWriter over the real cloud.google.com/go storage SDK.
type GCSWriter struct {
	ImpersonateSA string // a write-capable SA to impersonate in the customer project; "" → ADC
	// newClient builds the GCS client. Set by NewGCSWriter to the real SDK path; a test overrides it.
	newClient func(ctx context.Context, project string) (gcsBucketAPI, error)
}

// NewGCSWriter builds the live writer. impersonateSA is the cross-project WRITE service account to
// impersonate (empty → use Application Default Credentials, e.g. an attached SA).
func NewGCSWriter(impersonateSA string) *GCSWriter {
	w := &GCSWriter{ImpersonateSA: impersonateSA}
	w.newClient = w.realClient
	return w
}

// EnforceBucketPublicAccessPrevention enforces Public Access Prevention on the bucket — reversible,
// idempotent — the fix for a publicly-exposed GCS bucket.
func (w *GCSWriter) EnforceBucketPublicAccessPrevention(ctx context.Context, project, bucket string) error {
	if bucket == "" {
		return fmt.Errorf("gcpremediate: empty bucket")
	}
	client, err := w.newClient(ctx, project)
	if err != nil {
		return fmt.Errorf("gcpremediate: build gcs client: %w", err)
	}
	defer client.Close()
	if err := client.EnforcePublicAccessPrevention(ctx, bucket); err != nil {
		return fmt.Errorf("gcpremediate: enforce public-access-prevention(%s): %w", bucket, err)
	}
	return nil
}

// realClient builds the live GCS client (optionally impersonating the write SA), wrapped to the
// minimal API. The only code touching credentials/network — replaced by a fake in tests.
func (w *GCSWriter) realClient(ctx context.Context, _ string) (gcsBucketAPI, error) {
	var opts []option.ClientOption
	if w.ImpersonateSA != "" {
		ts, err := impersonate.CredentialsTokenSource(ctx, impersonate.CredentialsConfig{
			TargetPrincipal: w.ImpersonateSA,
			Scopes:          []string{storage.ScopeFullControl},
		})
		if err != nil {
			return nil, err
		}
		opts = append(opts, option.WithTokenSource(ts))
	}
	c, err := storage.NewClient(ctx, opts...)
	if err != nil {
		return nil, err
	}
	return &realGCS{c: c}, nil
}

type realGCS struct{ c *storage.Client }

func (r *realGCS) EnforcePublicAccessPrevention(ctx context.Context, bucket string) error {
	_, err := r.c.Bucket(bucket).Update(ctx, storage.BucketAttrsToUpdate{
		PublicAccessPrevention: storage.PublicAccessPreventionEnforced,
	})
	return err
}

func (r *realGCS) Close() error { return r.c.Close() }
