package runner

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ClatTribe/tsengine/internal/connector/awsfetch"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

type fakeTrail struct {
	page  awsfetch.EventPage
	err   error
	since time.Time
	until time.Time
	calls int
}

func (f *fakeTrail) LookupEvents(_ context.Context, since, until time.Time) (awsfetch.EventPage, error) {
	f.calls++
	f.since, f.until = since, until
	if f.err != nil {
		return awsfetch.EventPage{}, f.err
	}
	return f.page, nil
}

const ctRoot = `{"userIdentity":{"type":"Root","arn":"arn:aws:iam::1:root"},"eventName":"ConsoleLogin","awsRegion":"us-east-1","sourceIPAddress":"203.0.113.9"}`
const ctBenign = `{"userIdentity":{"type":"IAMUser","arn":"arn:aws:iam::1:user/dev"},"eventName":"DescribeInstances","awsRegion":"us-east-1"}`

// The pass polls CloudTrail through the AWS connection, detects over the records, stores the
// findings, folds them, and advances the cursor only to the newest event actually read.
func TestSyncCloudEvents_ReadsDetectsStoresAndAdvancesTheCursor(t *testing.T) {
	st := store.NewMemory()
	ctx := context.Background()
	_ = st.PutTenant(ctx, platform.Tenant{ID: "t1"})
	_ = st.PutConnection(ctx, platform.Connection{ID: "aws1", TenantID: "t1", Kind: platform.ConnAWS, Status: platform.ConnActive, SecretRef: "arn:aws:iam::1:role/ro"})
	_ = st.PutConnection(ctx, platform.Connection{ID: "gh1", TenantID: "t1", Kind: platform.ConnGitHub, Status: platform.ConnActive})
	now := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
	newest := now.Add(-10 * time.Minute)
	tr := &fakeTrail{page: awsfetch.EventPage{Records: [][]byte{[]byte(ctBenign), []byte(ctRoot), []byte("garbage")}, Latest: newest, Oldest: now.Add(-30 * time.Minute)}}
	var got []platform.Connection
	n := 0
	svc := &Service{Store: st, NewID: func() string { n++; return itoa(n) }, Now: func() time.Time { return now },
		CloudEventReader: func(c platform.Connection) awsfetch.EventReader { got = append(got, c); return tr }}

	res, ran := svc.SyncCloudEvents(ctx, "t1")
	if !ran {
		t.Fatal("the trail was read → ran must be true")
	}
	if len(got) != 1 || got[0].ID != "aws1" {
		t.Errorf("only the AWS connection is polled, got %+v", got)
	}
	if !tr.since.Equal(now.Add(-CloudEventWindow)) || !tr.until.Equal(now) {
		t.Errorf("first read must span Window..now, got %v..%v", tr.since, tr.until)
	}
	if res.Records != 3 || res.Dropped != 1 || res.Events != 2 || len(res.Connections) != 1 {
		t.Errorf("result: records=%d dropped=%d events=%d conns=%v", res.Records, res.Dropped, res.Events, res.Connections)
	}
	rules := map[string]bool{}
	for _, f := range res.Findings {
		rules[f.RuleID] = true
		if f.ID == "" {
			t.Error("stored finding has no id")
		}
	}
	if !rules["cloudcdr::root_console_login"] || len(res.Findings) != 1 {
		t.Errorf("the root login must be stored and nothing else: %v", rules)
	}
	stored, _ := st.ListFindings(ctx, "t1", store.FindingFilter{})
	if len(stored) != 1 {
		t.Errorf("findings must be persisted: %d", len(stored))
	}
	tn, _ := st.GetTenant(ctx, "t1")
	if got := tn.CloudEventCursors["aws1"]; !got.Equal(newest) {
		t.Errorf("cursor must be the newest event READ, got %v", got)
	}
	if _, ok := tn.PostureAssessed["cloudcdr"]; !ok {
		t.Error("the pass must stamp cloudcdr as assessed")
	}
	if len(res.Unread) != 0 {
		t.Errorf("a complete read leaves nothing unread: %v", res.Unread)
	}

	// Second pass: reads from cursor minus the overlap; an empty read does not move the cursor.
	tr.page = awsfetch.EventPage{}
	if _, ran := svc.SyncCloudEvents(ctx, "t1"); !ran {
		t.Fatal("an empty window is still a read")
	}
	if !tr.since.Equal(newest.Add(-CloudEventOverlap)) {
		t.Errorf("second read must start at cursor - overlap, got %v", tr.since)
	}
	tn, _ = st.GetTenant(ctx, "t1")
	if got := tn.CloudEventCursors["aws1"]; !got.Equal(newest) {
		t.Errorf("an empty read must not move the cursor, got %v", got)
	}
}

// A failed read is NOT an empty window: named in Failed, ran false, cursor untouched. No reader
// wired → not run at all. An inactive connection is skipped.
func TestSyncCloudEvents_FailedReadIsNotAnEmptyWindow(t *testing.T) {
	st := store.NewMemory()
	ctx := context.Background()
	_ = st.PutTenant(ctx, platform.Tenant{ID: "t1"})
	_ = st.PutConnection(ctx, platform.Connection{ID: "aws1", TenantID: "t1", Kind: platform.ConnAWS, Status: platform.ConnActive})
	_ = st.PutConnection(ctx, platform.Connection{ID: "aws2", TenantID: "t1", Kind: platform.ConnAWS, Status: platform.ConnQuarantined})
	tr := &fakeTrail{err: errors.New("AccessDenied: cloudtrail:LookupEvents")}
	svc := &Service{Store: st, NewID: func() string { return "x" },
		CloudEventReader: func(platform.Connection) awsfetch.EventReader { return tr }}
	res, ran := svc.SyncCloudEvents(ctx, "t1")
	if ran {
		t.Fatal("nothing was read → ran must be false, or the pass would mark cloudcdr covered")
	}
	if res.Failed["aws1"] == "" || len(res.Failed) != 1 || tr.calls != 1 {
		t.Errorf("the failure must be named once and the quarantined connection skipped: %+v calls=%d", res.Failed, tr.calls)
	}
	tn, _ := st.GetTenant(ctx, "t1")
	if len(tn.CloudEventCursors) != 0 {
		t.Error("a failed read moved the cursor")
	}
	if _, ran := (&Service{Store: st, NewID: func() string { return "x" }}).SyncCloudEvents(ctx, "t1"); ran {
		t.Error("no reader wired must not run")
	}
}

// A truncated read still advances the cursor (so the poller never loops on the same newest records)
// but NAMES the older span it did not examine, because "0 threats" over a partial window is a
// different claim from "0 threats" over a complete one.
func TestSyncCloudEvents_TruncatedReadNamesTheUnreadSpan(t *testing.T) {
	st := store.NewMemory()
	ctx := context.Background()
	_ = st.PutTenant(ctx, platform.Tenant{ID: "t1"})
	_ = st.PutConnection(ctx, platform.Connection{ID: "aws1", TenantID: "t1", Kind: platform.ConnAWS, Status: platform.ConnActive})
	now := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
	tr := &fakeTrail{page: awsfetch.EventPage{Records: [][]byte{[]byte(ctBenign)}, Latest: now.Add(-time.Minute), Oldest: now.Add(-5 * time.Minute), Truncated: true}}
	svc := &Service{Store: st, NewID: func() string { return "x" }, Now: func() time.Time { return now },
		CloudEventReader: func(platform.Connection) awsfetch.EventReader { return tr }}
	res, ran := svc.SyncCloudEvents(ctx, "t1")
	if !ran {
		t.Fatal("a truncated read is still a read")
	}
	msg := res.Unread["aws1"]
	if msg == "" || !strings.Contains(msg, now.Add(-5*time.Minute).Format(time.RFC3339)) || !strings.Contains(msg, "not examined") {
		t.Errorf("the unread span must be named with its bound: %q", msg)
	}
	tn, _ := st.GetTenant(ctx, "t1")
	if !tn.CloudEventCursors["aws1"].Equal(now.Add(-time.Minute)) {
		t.Errorf("cursor must still advance past the newest record read, got %v", tn.CloudEventCursors["aws1"])
	}
}
