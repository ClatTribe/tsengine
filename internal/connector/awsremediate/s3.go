// Package awsremediate is the LIVE AWS write path for cloud remediation — the SDK-backed
// implementation of connector.AWSWriter that connector.AWS.Apply routes to (it returns an honest
// "no live write path" stub when no writer is wired). It is a SEPARATE package so the AWS SDK
// dependency stays out of the core connector package (which the read-only OAuth connectors share
// and unit-test without any SDK).
//
// Today it implements the one reversible cloud remediation the engine proposes: enabling S3 Block
// Public Access on a publicly-exposed bucket. The call is reached ONLY after the HITL gate
// (§18.2 inv. 3) — the writer never acts on its own. Writes need real WRITE credentials, distinct
// from the read-only onboarding role; the writer assumes a configured write role (cross-account,
// scoped) before the call, so a compromise of the platform's ambient creds can't write to a
// customer account without the explicit role grant.
package awsremediate

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// s3PublicAccessBlockAPI is the minimal S3 surface the writer uses — so a test injects a fake
// without any AWS credentials (the connector.AWSWriter / Okta-Apply testing pattern).
type s3PublicAccessBlockAPI interface {
	PutPublicAccessBlock(ctx context.Context, params *s3.PutPublicAccessBlockInput, optFns ...func(*s3.Options)) (*s3.PutPublicAccessBlockOutput, error)
}

// S3Writer implements connector.AWSWriter (BlockS3PublicAccess) over the real AWS SDK.
type S3Writer struct {
	Region     string // the client region; "" → us-east-1
	RoleARN    string // the write-capable role to assume in the customer account; "" → ambient creds
	ExternalID string // the assume-role ExternalId (tenant binding), if the role requires one
	// newClient builds the S3 client. Set by NewS3Writer to the real SDK path; a test overrides it.
	newClient func(ctx context.Context) (s3PublicAccessBlockAPI, error)
}

// NewS3Writer builds the live writer. roleARN is the cross-account WRITE role to assume (empty →
// use the process's ambient AWS credentials, e.g. an attached instance/task role).
func NewS3Writer(region, roleARN, externalID string) *S3Writer {
	w := &S3Writer{Region: region, RoleARN: roleARN, ExternalID: externalID}
	w.newClient = w.realClient
	return w
}

// BlockS3PublicAccess enables S3 Block Public Access on the bucket — all four flags on — the
// reversible fix for a publicly-exposed-bucket finding. Idempotent (re-applying is a no-op).
func (w *S3Writer) BlockS3PublicAccess(ctx context.Context, bucket string) error {
	if bucket == "" {
		return fmt.Errorf("awsremediate: empty bucket")
	}
	client, err := w.newClient(ctx)
	if err != nil {
		return fmt.Errorf("awsremediate: build s3 client: %w", err)
	}
	_, err = client.PutPublicAccessBlock(ctx, &s3.PutPublicAccessBlockInput{
		Bucket: aws.String(bucket),
		PublicAccessBlockConfiguration: &s3types.PublicAccessBlockConfiguration{
			BlockPublicAcls:       aws.Bool(true),
			IgnorePublicAcls:      aws.Bool(true),
			BlockPublicPolicy:     aws.Bool(true),
			RestrictPublicBuckets: aws.Bool(true),
		},
	})
	if err != nil {
		return fmt.Errorf("awsremediate: PutPublicAccessBlock(%s): %w", bucket, err)
	}
	return nil
}

// realClient loads ambient AWS config, optionally assumes the customer's write role via STS, and
// returns a live S3 client. This is the only code that touches credentials/network — replaced by a
// fake in tests via newClient.
func (w *S3Writer) realClient(ctx context.Context) (s3PublicAccessBlockAPI, error) {
	region := w.Region
	if region == "" {
		region = "us-east-1"
	}
	cfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(region))
	if err != nil {
		return nil, err
	}
	if w.RoleARN != "" {
		stsClient := sts.NewFromConfig(cfg)
		provider := stscreds.NewAssumeRoleProvider(stsClient, w.RoleARN, func(o *stscreds.AssumeRoleOptions) {
			if w.ExternalID != "" {
				o.ExternalID = aws.String(w.ExternalID)
			}
		})
		cfg.Credentials = aws.NewCredentialsCache(provider)
	}
	return s3.NewFromConfig(cfg), nil
}
