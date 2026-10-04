package awsfetch

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudfront"
	cftypes "github.com/aws/aws-sdk-go-v2/service/cloudfront/types"
)

// DistributionReader reads the account's CloudFront distributions. CloudFront is global, so this is read
// once, not per region (cloudfront:ListDistributions is a READ).
type DistributionReader interface {
	ListDistributions(ctx context.Context) ([]Distribution, error)
}

// Distribution is one CloudFront distribution as the lister reports it.
type Distribution struct {
	ARN, ID, DomainName string
	Aliases             []string
	Enabled             bool
	// ViewerRestricted is true only when the default behaviour AND every other cache behaviour require
	// signed URLs or cookies. One open behaviour is an open door, so anything less is not restricted.
	ViewerRestricted bool
	Origins          []string
}

type cloudfrontAPI interface {
	ListDistributions(ctx context.Context, in *cloudfront.ListDistributionsInput, opts ...func(*cloudfront.Options)) (*cloudfront.ListDistributionsOutput, error)
}

// CloudFrontLister reads through the connected read-only role.
type CloudFrontLister struct {
	RoleARN    string
	ExternalID string
	MaxPages   int // default 50

	api cloudfrontAPI // injected in tests
}

func NewCloudFrontLister(roleARN, externalID string) *CloudFrontLister {
	return &CloudFrontLister{RoleARN: roleARN, ExternalID: externalID}
}

func (l *CloudFrontLister) client(ctx context.Context) (cloudfrontAPI, error) {
	if l.api != nil {
		return l.api, nil
	}
	// CloudFront's control plane is served from us-east-1 whatever region the rest of the read uses.
	cfg, err := assumeRoleConfig(ctx, "us-east-1", l.RoleARN, l.ExternalID)
	if err != nil {
		return nil, err
	}
	return cloudfront.NewFromConfig(cfg), nil
}

func (l *CloudFrontLister) ListDistributions(ctx context.Context) ([]Distribution, error) {
	api, err := l.client(ctx)
	if err != nil {
		return nil, err
	}
	max := l.MaxPages
	if max <= 0 {
		max = 50
	}
	var out []Distribution
	var marker *string
	for page := 0; ; page++ {
		if page >= max {
			return nil, fmt.Errorf("awsfetch: distribution listing exceeded %d pages; refusing a partial list that would read as complete", max)
		}
		res, err := api.ListDistributions(ctx, &cloudfront.ListDistributionsInput{Marker: marker})
		if err != nil {
			return nil, fmt.Errorf("awsfetch: list distributions: %w", err)
		}
		if res.DistributionList == nil {
			break
		}
		for _, d := range res.DistributionList.Items {
			out = append(out, summarize(d))
		}
		if !aws.ToBool(res.DistributionList.IsTruncated) || aws.ToString(res.DistributionList.NextMarker) == "" {
			break
		}
		marker = res.DistributionList.NextMarker
	}
	return out, nil
}

func summarize(d cftypes.DistributionSummary) Distribution {
	o := Distribution{
		ARN: aws.ToString(d.ARN), ID: aws.ToString(d.Id), DomainName: aws.ToString(d.DomainName),
		Enabled: aws.ToBool(d.Enabled),
	}
	if d.Aliases != nil {
		o.Aliases = d.Aliases.Items
	}
	if d.Origins != nil {
		for _, or := range d.Origins.Items {
			if dn := aws.ToString(or.DomainName); dn != "" {
				o.Origins = append(o.Origins, dn)
			}
		}
	}
	restricted := d.DefaultCacheBehavior != nil &&
		signedOnly(d.DefaultCacheBehavior.TrustedKeyGroups, d.DefaultCacheBehavior.TrustedSigners)
	if restricted && d.CacheBehaviors != nil {
		for _, cb := range d.CacheBehaviors.Items {
			if !signedOnly(cb.TrustedKeyGroups, cb.TrustedSigners) {
				restricted = false
				break
			}
		}
	}
	o.ViewerRestricted = restricted
	return o
}

func signedOnly(kg *cftypes.TrustedKeyGroups, ts *cftypes.TrustedSigners) bool {
	return (kg != nil && aws.ToBool(kg.Enabled)) || (ts != nil && aws.ToBool(ts.Enabled))
}
