package awsfetch

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
)

// EventReader reads the account's CloudTrail management-event history for a window. It returns the
// RAW records (the CloudTrailEvent JSON) rather than a decoded shape, because the decoding into the
// CDR detector's Event is cloudcdr's job and keeping the translation in ONE place is what lets the
// posted-event door and the polled door agree on what an event means.
type EventReader interface {
	LookupEvents(ctx context.Context, since, until time.Time) (EventPage, error)
}

// EventPage is what one window read returned.
type EventPage struct {
	Records [][]byte  // CloudTrailEvent JSON, oldest first
	Latest  time.Time // newest event time in the page; zero when no events
	Oldest  time.Time // oldest event time in the page; zero when no events
	// Truncated is true when the read stopped at MaxRecords before the window was exhausted. The
	// API returns NEWEST first, so what went unread is the OLDER span [since, Oldest) — and it stays
	// unread: the caller advances its cursor past Latest regardless (or every pass would re-read the
	// same newest records and never reach the rest) and NAMES the span it did not look at, because
	// "0 threats" over a truncated read is not the same claim as over a complete one.
	Truncated bool
}

type cloudtrailAPI interface {
	LookupEvents(ctx context.Context, in *cloudtrail.LookupEventsInput, opts ...func(*cloudtrail.Options)) (*cloudtrail.LookupEventsOutput, error)
}

// CloudTrailLister reads the 90-day event history CloudTrail keeps for every account with NO trail
// configured (cloudtrail:LookupEvents — a READ permission in ReadOnlyAccess and ViewOnlyAccess). It
// is the honest floor of the CDR capability: management events only, one region per lister, up to
// ~15 minutes behind real time, and rate-limited by AWS to two calls a second. A customer with an
// organisation trail into S3 or an EventBridge rule gets more; this gets everyone something without
// a pipeline they would have to build.
type CloudTrailLister struct {
	Region     string
	RoleARN    string
	ExternalID string
	// MaxRecords bounds one read (default 2000 — 40 pages at the API's 50-per-page). A busy account
	// can write thousands of management events an hour; the bound keeps a pass finite and the
	// Truncated flag keeps the cursor honest.
	MaxRecords int

	api cloudtrailAPI // injected in tests
}

func NewCloudTrailLister(region, roleARN, externalID string) *CloudTrailLister {
	return &CloudTrailLister{Region: region, RoleARN: roleARN, ExternalID: externalID}
}

func (l *CloudTrailLister) client(ctx context.Context) (cloudtrailAPI, error) {
	if l.api != nil {
		return l.api, nil
	}
	cfg, err := assumeRoleConfig(ctx, l.Region, l.RoleARN, l.ExternalID)
	if err != nil {
		return nil, err
	}
	return cloudtrail.NewFromConfig(cfg), nil
}

// LookupEvents reads [since, until]. The API returns newest-first; the page is reversed so the
// detector sees events in the order they happened (its sequence rules depend on it).
func (l *CloudTrailLister) LookupEvents(ctx context.Context, since, until time.Time) (EventPage, error) {
	api, err := l.client(ctx)
	if err != nil {
		return EventPage{}, err
	}
	limit := l.MaxRecords
	if limit <= 0 {
		limit = 2000
	}
	var page EventPage
	var token *string
	for {
		res, err := api.LookupEvents(ctx, &cloudtrail.LookupEventsInput{
			StartTime: aws.Time(since), EndTime: aws.Time(until), NextToken: token, MaxResults: aws.Int32(50),
		})
		if err != nil {
			return EventPage{}, fmt.Errorf("awsfetch: cloudtrail lookup events: %w", err)
		}
		for _, e := range res.Events {
			if e.CloudTrailEvent == nil || *e.CloudTrailEvent == "" {
				continue
			}
			page.Records = append(page.Records, []byte(*e.CloudTrailEvent))
			if e.EventTime != nil {
				if e.EventTime.After(page.Latest) {
					page.Latest = *e.EventTime
				}
				if page.Oldest.IsZero() || e.EventTime.Before(page.Oldest) {
					page.Oldest = *e.EventTime
				}
			}
			if len(page.Records) >= limit {
				page.Truncated = res.NextToken != nil && *res.NextToken != ""
				break
			}
		}
		if len(page.Records) >= limit || res.NextToken == nil || *res.NextToken == "" {
			break
		}
		token = res.NextToken
	}
	// Oldest first.
	for i, j := 0, len(page.Records)-1; i < j; i, j = i+1, j-1 {
		page.Records[i], page.Records[j] = page.Records[j], page.Records[i]
	}
	return page, nil
}
