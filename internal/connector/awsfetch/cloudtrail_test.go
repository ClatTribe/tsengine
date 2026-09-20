package awsfetch

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	cttypes "github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
)

// fakeCloudTrailAPI serves N events newest-first across pages of `per`, as the real API does.
type fakeCloudTrailAPI struct {
	n, per int
	base   time.Time
	calls  int
	in     []*cloudtrail.LookupEventsInput
}

func (f *fakeCloudTrailAPI) LookupEvents(_ context.Context, in *cloudtrail.LookupEventsInput, _ ...func(*cloudtrail.Options)) (*cloudtrail.LookupEventsOutput, error) {
	f.calls++
	f.in = append(f.in, in)
	start := 0
	if in.NextToken != nil {
		fmt.Sscanf(*in.NextToken, "%d", &start)
	}
	out := &cloudtrail.LookupEventsOutput{}
	for i := start; i < f.n && i < start+f.per; i++ {
		// i=0 is the NEWEST.
		at := f.base.Add(-time.Duration(i) * time.Minute)
		out.Events = append(out.Events, cttypes.Event{
			EventTime:       aws.Time(at),
			CloudTrailEvent: aws.String(fmt.Sprintf(`{"eventName":"E%d","eventTime":"%s"}`, i, at.Format(time.RFC3339))),
		})
	}
	if start+f.per < f.n {
		out.NextToken = aws.String(fmt.Sprintf("%d", start+f.per))
	}
	return out, nil
}

// The lister pages through the window, hands the records back OLDEST first (the detector's sequence
// rules depend on order), and reports the newest and oldest event times it saw.
func TestCloudTrailLister_PagesAndReturnsOldestFirst(t *testing.T) {
	base := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
	api := &fakeCloudTrailAPI{n: 7, per: 3, base: base}
	l := &CloudTrailLister{Region: "us-east-1", api: api}
	page, err := l.LookupEvents(context.Background(), base.Add(-time.Hour), base)
	if err != nil {
		t.Fatal(err)
	}
	if api.calls != 3 || len(page.Records) != 7 {
		t.Fatalf("want 3 pages / 7 records, got %d / %d", api.calls, len(page.Records))
	}
	if string(page.Records[0]) == "" || string(page.Records[0])[len(`{"eventName":"E`):len(`{"eventName":"E`)+1] != "6" {
		t.Errorf("first record must be the OLDEST (E6), got %s", page.Records[0])
	}
	if !page.Latest.Equal(base) || !page.Oldest.Equal(base.Add(-6*time.Minute)) || page.Truncated {
		t.Errorf("latest/oldest/truncated: %v %v %v", page.Latest, page.Oldest, page.Truncated)
	}
	if got := api.in[0]; !aws.ToTime(got.StartTime).Equal(base.Add(-time.Hour)) || !aws.ToTime(got.EndTime).Equal(base) {
		t.Errorf("the window must be passed through: %v..%v", got.StartTime, got.EndTime)
	}
}

// A read that hits MaxRecords with more pages left is TRUNCATED: it reports so and names the oldest
// record it did read, so the caller can say which span went unexamined instead of reading "clean".
func TestCloudTrailLister_TruncationIsReportedNotSilent(t *testing.T) {
	base := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
	api := &fakeCloudTrailAPI{n: 10, per: 4, base: base}
	l := &CloudTrailLister{Region: "us-east-1", MaxRecords: 5, api: api}
	page, err := l.LookupEvents(context.Background(), base.Add(-time.Hour), base)
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Records) != 5 || !page.Truncated {
		t.Fatalf("want 5 records truncated, got %d truncated=%v", len(page.Records), page.Truncated)
	}
	if !page.Oldest.Equal(base.Add(-4 * time.Minute)) {
		t.Errorf("oldest read must be E4 (newest-first read stopped there), got %v", page.Oldest)
	}
	// Exactly at the bound with no page left is NOT truncated.
	api2 := &fakeCloudTrailAPI{n: 5, per: 5, base: base}
	l2 := &CloudTrailLister{Region: "us-east-1", MaxRecords: 5, api: api2}
	if p2, _ := l2.LookupEvents(context.Background(), base.Add(-time.Hour), base); p2.Truncated {
		t.Error("a window that fit exactly must not read as truncated")
	}
}
