package runner

import (
	"context"
	"testing"
	"time"

	"github.com/ClatTribe/tsengine/internal/connector/awsfetch"
	"github.com/ClatTribe/tsengine/internal/detect"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

type fakeGDReader struct {
	page awsfetch.GuardDutyPage
	err  error
}

func (f fakeGDReader) FindingsSince(context.Context, time.Time) (awsfetch.GuardDutyPage, error) {
	return f.page, f.err
}

func gdFixture(t *testing.T, r fakeGDReader) (*store.Memory, *Service) {
	t.Helper()
	st := store.NewMemory()
	ctx := context.Background()
	_ = st.PutTenant(ctx, platform.Tenant{ID: "t1"})
	_ = st.PutConnection(ctx, platform.Connection{ID: "aws1", TenantID: "t1", Kind: platform.ConnAWS, Status: platform.ConnActive})
	now := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	n := 0
	id := func() string { n++; return itoa(n) }
	return st, &Service{Store: st, NewID: id, Now: func() time.Time { return now },
		GuardDutyReader: func(platform.Connection) awsfetch.GuardDutyReader { return r },
		Detector:        &detect.Detector{Store: st, NewID: id, Now: func() time.Time { return now }}}
}

// GuardDuty's verdict is carried as GuardDuty's: its own severity band, its own type, named as its report.
// Re-reading the same finding updates it rather than storing it again, and the fast poll opens an incident.
func TestSyncGuardDuty_StoresGuardDutysVerdictOnce(t *testing.T) {
	ctx := context.Background()
	page := awsfetch.GuardDutyPage{Latest: time.Date(2026, 10, 5, 11, 0, 0, 0, time.UTC), Findings: []awsfetch.GuardDutyFinding{
		{ID: "gd-1", Type: "CryptoCurrency:EC2/BitcoinTool.B!DNS", Title: "EC2 instance querying a crypto-mining domain", Severity: 8.0, Resource: "i-abc"},
	}}
	st, svc := gdFixture(t, fakeGDReader{page: page})
	res := svc.PollEvents(ctx, "t1")
	if !res.GuardDutyRead || res.Opened != 1 {
		t.Fatalf("poll: %+v", res)
	}
	svc.PollEvents(ctx, "t1")
	fs, _ := st.ListFindings(ctx, "t1", store.FindingFilter{})
	if len(fs) != 1 {
		t.Fatalf("one GuardDuty finding read twice must be stored once, got %d", len(fs))
	}
	f := fs[0]
	if f.Severity != types.SeverityHigh || f.RuleID != "guardduty::CryptoCurrency:EC2/BitcoinTool.B!DNS" || f.Endpoint != "cloud:i-abc" {
		t.Errorf("finding: %+v", f)
	}
	if tn, _ := st.GetTenant(ctx, "t1"); !tn.GuardDutyCursors["aws1"].Equal(page.Latest) {
		t.Errorf("cursor: %v", tn.GuardDutyCursors)
	}
}

// An account without GuardDuty enabled is unwatched, not clean: not counted as read, and named.
func TestSyncGuardDuty_NotEnabledIsNotARead(t *testing.T) {
	_, svc := gdFixture(t, fakeGDReader{page: awsfetch.GuardDutyPage{NotEnabled: true}, err: awsfetch.ErrGuardDutyNotEnabled})
	res, ran := svc.SyncGuardDuty(context.Background(), "t1")
	if ran || len(res.NotEnabled) != 1 || len(res.Connections) != 0 {
		t.Fatalf("an unwatched region was read as clean: ran=%v %+v", ran, res)
	}
}

func TestGuardDutySeverityBands(t *testing.T) {
	for score, want := range map[float64]types.Severity{9.5: types.SeverityCritical, 9.0: types.SeverityCritical,
		8.9: types.SeverityHigh, 7.0: types.SeverityHigh, 5.0: types.SeverityMedium, 1.0: types.SeverityLow} {
		if got := guardDutySeverity(score); got != want {
			t.Errorf("%.1f → %s, want %s", score, got, want)
		}
	}
}
