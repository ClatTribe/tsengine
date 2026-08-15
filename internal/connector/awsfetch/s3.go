package awsfetch

import (
	"context"
	"errors"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// s3.go is the live object-store read, through the customer's scoped read-only role.
//
// It mirrors awsremediate.S3Writer: the SDK calls sit behind a narrow interface so the logic is
// testable without credentials, and the role is assumed lazily with the connection's external id.
// Read-only by construction — this package has no PUT of any kind, so a mistake here cannot mutate a
// customer's account.

// s3API is the slice of S3 this needs. Narrow on purpose: the fewer calls named here, the smaller the
// permission the customer has to grant and the less this can do if it is ever wrong.
type s3API interface {
	ListBuckets(ctx context.Context, in *s3.ListBucketsInput, opts ...func(*s3.Options)) (*s3.ListBucketsOutput, error)
	GetPublicAccessBlock(ctx context.Context, in *s3.GetPublicAccessBlockInput, opts ...func(*s3.Options)) (*s3.GetPublicAccessBlockOutput, error)
	GetBucketLocation(ctx context.Context, in *s3.GetBucketLocationInput, opts ...func(*s3.Options)) (*s3.GetBucketLocationOutput, error)
}

// S3Lister reads buckets and their public-access posture via an assumed role.
type S3Lister struct {
	Region     string
	RoleARN    string // the customer's cross-account READ-ONLY role
	ExternalID string // the per-tenant external id issued at connect time (confused-deputy guard)

	api s3API // injected in tests; built lazily in production
}

// NewS3Lister builds the live lister. It performs no I/O — credentials are resolved on first use, so
// constructing one on a deployment with no AWS access is harmless.
func NewS3Lister(region, roleARN, externalID string) *S3Lister {
	return &S3Lister{Region: region, RoleARN: roleARN, ExternalID: externalID}
}

// ListBuckets returns every bucket with its resolved public-access posture.
//
// PUBLIC IS ONLY REPORTED WHEN AWS SAYS SO. A bucket whose public-access-block cannot be read is left
// Public=false rather than guessed either way: calling it public would cry wolf on a bucket that is
// fine, and calling it public-unknown-but-probably-safe is the false clean this codebase refuses. The
// per-bucket error rides in the returned error only when EVERY bucket failed, so one unreadable
// bucket cannot hide the rest.
func (l *S3Lister) ListBuckets(ctx context.Context) ([]Bucket, error) {
	api, err := l.client(ctx)
	if err != nil {
		return nil, err
	}
	out, err := api.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		return nil, fmt.Errorf("awsfetch: list buckets: %w", err)
	}

	buckets := make([]Bucket, 0, len(out.Buckets))
	for _, b := range out.Buckets {
		if b.Name == nil {
			continue
		}
		name := *b.Name
		bk := Bucket{Name: name, Region: l.Region}

		// A bucket is PUBLIC when its public-access-block does not block public ACLs/policies. AWS
		// returns NoSuchPublicAccessBlockConfiguration when none is set at all — which genuinely means
		// nothing is blocking public access, so that case IS public.
		pab, perr := api.GetPublicAccessBlock(ctx, &s3.GetPublicAccessBlockInput{Bucket: aws.String(name)})
		switch {
		case perr != nil && isNoSuchPAB(perr):
			bk.Public = true
		case perr != nil:
			// Unreadable. Leave Public=false and say nothing about it rather than guess — see the
			// method comment. The bucket still appears in the inventory; only its posture is unknown.
		default:
			bk.Public = !blocksPublic(pab)
		}
		buckets = append(buckets, bk)
	}
	return buckets, nil
}

// blocksPublic reports whether the public-access-block genuinely blocks public access. All four flags
// must be set: AWS treats them independently, and three-of-four still leaves a way in.
func blocksPublic(out *s3.GetPublicAccessBlockOutput) bool {
	if out == nil || out.PublicAccessBlockConfiguration == nil {
		return false
	}
	c := out.PublicAccessBlockConfiguration
	return deref(c.BlockPublicAcls) && deref(c.BlockPublicPolicy) &&
		deref(c.IgnorePublicAcls) && deref(c.RestrictPublicBuckets)
}

func deref(b *bool) bool { return b != nil && *b }

// isNoSuchPAB recognises "no public-access-block is configured", which is a POSTURE fact (nothing is
// blocking public access), not a read failure.
func isNoSuchPAB(err error) bool {
	var ae interface{ ErrorCode() string }
	if errors.As(err, &ae) {
		return ae.ErrorCode() == "NoSuchPublicAccessBlockConfiguration"
	}
	return false
}

// client builds the assumed-role S3 client on first use, or returns the injected test double.
func (l *S3Lister) client(ctx context.Context) (s3API, error) {
	if l.api != nil {
		return l.api, nil
	}
	region := l.Region
	if region == "" {
		region = "us-east-1"
	}
	cfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(region))
	if err != nil {
		return nil, fmt.Errorf("awsfetch: load aws config: %w", err)
	}
	if l.RoleARN != "" {
		provider := stscreds.NewAssumeRoleProvider(sts.NewFromConfig(cfg), l.RoleARN,
			func(o *stscreds.AssumeRoleOptions) {
				if l.ExternalID != "" {
					o.ExternalID = aws.String(l.ExternalID)
				}
			})
		cfg.Credentials = aws.NewCredentialsCache(provider)
	}
	return s3.NewFromConfig(cfg), nil
}
