package awsfetch

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/guardduty"
	gdtypes "github.com/aws/aws-sdk-go-v2/service/guardduty/types"
)

// GuardDutyReader reads the findings AWS GuardDuty has raised in the account since a time. GuardDuty is
// AWS's own threat detector (credential misuse, crypto-mining, reconnaissance, malware, anomalous API
// calls); its verdicts are read as GuardDuty's, never re-judged. guardduty:ListDetectors, ListFindings and
// GetFindings are READ permissions in ReadOnlyAccess / SecurityAudit.
type GuardDutyReader interface {
	FindingsSince(ctx context.Context, since time.Time) (GuardDutyPage, error)
}

// GuardDutyFinding is one GuardDuty finding as the lister reports it.
type GuardDutyFinding struct {
	ID          string
	Type        string // e.g. "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS"
	Title       string
	Description string
	Severity    float64 // GuardDuty's own 1.0–10.0 score
	Region      string
	Resource    string // the affected resource as GuardDuty names it (instance id, access key, bucket, function ARN)
	UpdatedAt   time.Time
}

// GuardDutyPage is what one read returned.
type GuardDutyPage struct {
	Findings []GuardDutyFinding
	Latest   time.Time // newest UpdatedAt read; zero when nothing
	// NotEnabled is true when the region has no GuardDuty detector. That is NOT "no threats": nothing is
	// watching, and the caller must say so rather than report a quiet account.
	NotEnabled bool
	Truncated  bool // stopped at MaxFindings; the newest-first order means older updates went unread
}

// ErrGuardDutyNotEnabled is returned alongside a NotEnabled page so callers that only check errors cannot
// mistake an unwatched region for a clean one.
var ErrGuardDutyNotEnabled = errors.New("GuardDuty is not enabled in this region, so nothing is watching for these threats")

type guarddutyAPI interface {
	ListDetectors(ctx context.Context, in *guardduty.ListDetectorsInput, opts ...func(*guardduty.Options)) (*guardduty.ListDetectorsOutput, error)
	ListFindings(ctx context.Context, in *guardduty.ListFindingsInput, opts ...func(*guardduty.Options)) (*guardduty.ListFindingsOutput, error)
	GetFindings(ctx context.Context, in *guardduty.GetFindingsInput, opts ...func(*guardduty.Options)) (*guardduty.GetFindingsOutput, error)
}

// GuardDutyLister reads through the connected read-only role, one region per lister.
type GuardDutyLister struct {
	Region      string
	RoleARN     string
	ExternalID  string
	MaxFindings int // per read (default 500)

	api guarddutyAPI // injected in tests
}

func NewGuardDutyLister(region, roleARN, externalID string) *GuardDutyLister {
	return &GuardDutyLister{Region: region, RoleARN: roleARN, ExternalID: externalID}
}

func (l *GuardDutyLister) client(ctx context.Context) (guarddutyAPI, error) {
	if l.api != nil {
		return l.api, nil
	}
	cfg, err := assumeRoleConfig(ctx, l.Region, l.RoleARN, l.ExternalID)
	if err != nil {
		return nil, err
	}
	return guardduty.NewFromConfig(cfg), nil
}

// FindingsSince lists findings UPDATED since `since` (a finding that recurs is updated, not re-created, so
// updatedAt is the field that catches it again), excluding ones the customer archived in GuardDuty.
func (l *GuardDutyLister) FindingsSince(ctx context.Context, since time.Time) (GuardDutyPage, error) {
	api, err := l.client(ctx)
	if err != nil {
		return GuardDutyPage{}, err
	}
	dets, err := api.ListDetectors(ctx, &guardduty.ListDetectorsInput{})
	if err != nil {
		return GuardDutyPage{}, fmt.Errorf("awsfetch: list GuardDuty detectors: %w", err)
	}
	if len(dets.DetectorIds) == 0 {
		return GuardDutyPage{NotEnabled: true}, ErrGuardDutyNotEnabled
	}
	max := l.MaxFindings
	if max <= 0 {
		max = 500
	}
	var page GuardDutyPage
	for _, det := range dets.DetectorIds {
		criteria := &gdtypes.FindingCriteria{Criterion: map[string]gdtypes.Condition{
			"updatedAt":        {GreaterThanOrEqual: aws.Int64(since.UnixMilli())},
			"service.archived": {Equals: []string{"false"}},
		}}
		var ids []string
		var token *string
		for {
			res, err := api.ListFindings(ctx, &guardduty.ListFindingsInput{
				DetectorId: aws.String(det), FindingCriteria: criteria, NextToken: token,
				SortCriteria: &gdtypes.SortCriteria{AttributeName: aws.String("updatedAt"), OrderBy: gdtypes.OrderByDesc},
			})
			if err != nil {
				return GuardDutyPage{}, fmt.Errorf("awsfetch: list GuardDuty findings: %w", err)
			}
			ids = append(ids, res.FindingIds...)
			if len(ids) >= max {
				ids, page.Truncated = ids[:max], true
				break
			}
			if aws.ToString(res.NextToken) == "" {
				break
			}
			token = res.NextToken
		}
		for start := 0; start < len(ids); start += 50 {
			end := min(start+50, len(ids))
			got, err := api.GetFindings(ctx, &guardduty.GetFindingsInput{DetectorId: aws.String(det), FindingIds: ids[start:end]})
			if err != nil {
				return GuardDutyPage{}, fmt.Errorf("awsfetch: get GuardDuty findings: %w", err)
			}
			for _, f := range got.Findings {
				if f.Service != nil && aws.ToBool(f.Service.Archived) {
					continue
				}
				gf := GuardDutyFinding{
					ID: aws.ToString(f.Id), Type: aws.ToString(f.Type), Title: aws.ToString(f.Title),
					Description: aws.ToString(f.Description), Severity: aws.ToFloat64(f.Severity),
					Region: aws.ToString(f.Region), Resource: guardDutyResource(f.Resource),
				}
				if t, err := time.Parse(time.RFC3339, aws.ToString(f.UpdatedAt)); err == nil {
					gf.UpdatedAt = t
					if t.After(page.Latest) {
						page.Latest = t
					}
				}
				page.Findings = append(page.Findings, gf)
			}
		}
	}
	return page, nil
}

// guardDutyResource names the affected resource the way GuardDuty identifies it.
func guardDutyResource(r *gdtypes.Resource) string {
	if r == nil {
		return ""
	}
	switch {
	case r.InstanceDetails != nil && aws.ToString(r.InstanceDetails.InstanceId) != "":
		return aws.ToString(r.InstanceDetails.InstanceId)
	case r.AccessKeyDetails != nil && aws.ToString(r.AccessKeyDetails.AccessKeyId) != "":
		return aws.ToString(r.AccessKeyDetails.AccessKeyId)
	case len(r.S3BucketDetails) > 0:
		if a := aws.ToString(r.S3BucketDetails[0].Arn); a != "" {
			return a
		}
		return aws.ToString(r.S3BucketDetails[0].Name)
	case r.LambdaDetails != nil && aws.ToString(r.LambdaDetails.FunctionArn) != "":
		return aws.ToString(r.LambdaDetails.FunctionArn)
	}
	return aws.ToString(r.ResourceType)
}
