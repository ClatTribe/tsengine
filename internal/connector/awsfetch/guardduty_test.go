package awsfetch

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/guardduty"
	gdtypes "github.com/aws/aws-sdk-go-v2/service/guardduty/types"
)

type fakeGD struct {
	detectors []string
	findings  []gdtypes.Finding
	criteria  *gdtypes.FindingCriteria
}

func (f *fakeGD) ListDetectors(context.Context, *guardduty.ListDetectorsInput, ...func(*guardduty.Options)) (*guardduty.ListDetectorsOutput, error) {
	return &guardduty.ListDetectorsOutput{DetectorIds: f.detectors}, nil
}

func (f *fakeGD) ListFindings(_ context.Context, in *guardduty.ListFindingsInput, _ ...func(*guardduty.Options)) (*guardduty.ListFindingsOutput, error) {
	f.criteria = in.FindingCriteria
	var ids []string
	for _, x := range f.findings {
		ids = append(ids, aws.ToString(x.Id))
	}
	return &guardduty.ListFindingsOutput{FindingIds: ids}, nil
}

func (f *fakeGD) GetFindings(context.Context, *guardduty.GetFindingsInput, ...func(*guardduty.Options)) (*guardduty.GetFindingsOutput, error) {
	return &guardduty.GetFindingsOutput{Findings: f.findings}, nil
}

// A region with no GuardDuty detector is UNWATCHED, not clean: the read says so as a distinct state and
// an error, so a caller checking only errors cannot read it as a quiet account.
func TestGuardDuty_NotEnabledIsNotClean(t *testing.T) {
	page, err := (&GuardDutyLister{api: &fakeGD{}}).FindingsSince(context.Background(), time.Now())
	if !page.NotEnabled || !errors.Is(err, ErrGuardDutyNotEnabled) {
		t.Fatalf("no detector must be reported as not enabled: %+v %v", page, err)
	}
}

func TestGuardDuty_ReadsUnarchivedFindingsWithTheirResource(t *testing.T) {
	updated := "2026-10-05T10:00:00Z"
	f := &fakeGD{detectors: []string{"d1"}, findings: []gdtypes.Finding{
		{Id: aws.String("gd-1"), Type: aws.String("CryptoCurrency:EC2/BitcoinTool.B!DNS"), Severity: aws.Float64(8.0),
			UpdatedAt: aws.String(updated), Region: aws.String("us-east-1"),
			Resource: &gdtypes.Resource{InstanceDetails: &gdtypes.InstanceDetails{InstanceId: aws.String("i-abc")}}},
		{Id: aws.String("gd-2"), Type: aws.String("Recon:IAMUser/UserPermissions"), Severity: aws.Float64(2.0),
			UpdatedAt: aws.String(updated), Service: &gdtypes.Service{Archived: aws.Bool(true)}},
	}}
	page, err := (&GuardDutyLister{api: f}).FindingsSince(context.Background(), time.Unix(1, 0))
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Findings) != 1 || page.Findings[0].Resource != "i-abc" || page.Findings[0].Severity != 8.0 {
		t.Fatalf("archived findings are the customer's decision and must be skipped: %+v", page.Findings)
	}
	if page.Latest.Format(time.RFC3339) != updated {
		t.Errorf("latest: %v", page.Latest)
	}
	// Recurring findings are UPDATED, not re-created, so the window must filter on updatedAt, and the
	// customer's archive decision must be honoured server-side too.
	if _, ok := f.criteria.Criterion["updatedAt"]; !ok {
		t.Error("the read must filter on updatedAt")
	}
	if c, ok := f.criteria.Criterion["service.archived"]; !ok || len(c.Equals) != 1 || c.Equals[0] != "false" {
		t.Error("the read must exclude archived findings")
	}
}
