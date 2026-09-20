package runner

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ClatTribe/tsengine/internal/identitylog"
	"github.com/ClatTribe/tsengine/internal/identitythreat"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

type idTokens struct{ tok string }

func (f idTokens) Resolve(context.Context, platform.Connection) (string, error) {
	if f.tok == "" {
		return "", errors.New("sealed ref unreadable")
	}
	return f.tok, nil
}

type fakeLog struct {
	events []identitythreat.Event
	err    error
	since  time.Time
	token  string
}

func (f *fakeLog) Fetch(_ context.Context, token string, since time.Time) (identitylog.Report, error) {
	f.since, f.token = since, token
	if f.err != nil {
		return identitylog.Report{}, f.err
	}
	return identitylog.Report{Provider: "okta", Fetched: len(f.events), Events: f.events,
		ChecksNotRun: map[string]string{"mfa_fatigue": "not in this log"}}, nil
}

func sprayEvents(at time.Time) []identitythreat.Event {
	var evs []identitythreat.Event
	for i := 0; i < 6; i++ {
		evs = append(evs, identitythreat.Event{ID: "f" + itoa(i), User: "ada@acme.io", Type: identitythreat.EventLoginFail,
			Time: at.Add(time.Duration(i) * time.Minute), IP: "203.0.113.9"})
	}
	return evs
}

// The pass reads the log through the onboarded connection's token, detects over it, stores the
// findings, and advances the cursor only to the newest event actually read.
func TestSyncIdentityLogs_ReadsDetectsStoresAndAdvancesTheCursor(t *testing.T) {
	st := store.NewMemory()
	ctx := context.Background()
	_ = st.PutTenant(ctx, platform.Tenant{ID: "t1"})
	_ = st.PutConnection(ctx, platform.Connection{ID: "c1", TenantID: "t1", Kind: platform.ConnOkta, Status: platform.ConnActive, SecretRef: "sealed"})
	now := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
	at := now.Add(-30 * time.Minute)
	f := &fakeLog{events: sprayEvents(at)}
	n := 0
	svc := &Service{Store: st, Tokens: idTokens{tok: "okta-token"}, NewID: func() string { n++; return itoa(n) },
		Now: func() time.Time { return now }, IdentityLogFetchers: map[string]identitylog.Fetcher{platform.ConnOkta: f}}

	res, ran := svc.SyncIdentityLogs(ctx, "t1")
	if !ran {
		t.Fatal("the log was read → ran must be true")
	}
	if f.token != "okta-token" {
		t.Errorf("the fetcher must receive the connection's resolved token, got %q", f.token)
	}
	if !f.since.Equal(now.Add(-identitylog.Window)) {
		t.Errorf("first read must start Window ago, got %v", f.since)
	}
	if res.Events != 6 || len(res.Providers) != 1 || res.Providers[0] != platform.ConnOkta {
		t.Errorf("result: %+v", res)
	}
	rules := map[string]bool{}
	for _, fd := range res.Findings {
		rules[fd.RuleID] = true
		if fd.ID == "" {
			t.Error("stored finding has no id")
		}
	}
	if !rules["identitythreat::password_spray"] {
		t.Errorf("a six-failure spray must be stored as a finding; got %v", rules)
	}
	stored, _ := st.ListFindings(ctx, "t1", store.FindingFilter{})
	if len(stored) != len(res.Findings) || len(stored) == 0 {
		t.Errorf("findings must be persisted: stored %d, reported %d", len(stored), len(res.Findings))
	}
	if _, ok := res.ChecksNotRun["okta:mfa_fatigue"]; !ok {
		t.Error("what the provider's log cannot answer must ride into the result")
	}
	tn, _ := st.GetTenant(ctx, "t1")
	if got := tn.IdentityLogCursors[platform.ConnOkta]; !got.Equal(at.Add(5 * time.Minute)) {
		t.Errorf("cursor must be the newest event READ, got %v", got)
	}
	if _, ok := tn.PostureAssessed["identitythreat"]; !ok {
		t.Error("the pass must stamp identitythreat as assessed")
	}

	// Second pass: reads from cursor minus the overlap, not from the beginning of time.
	f.events = nil
	if _, ran := svc.SyncIdentityLogs(ctx, "t1"); !ran {
		t.Fatal("an empty window is still a read")
	}
	if !f.since.Equal(at.Add(5 * time.Minute).Add(-identitylog.Overlap)) {
		t.Errorf("second read must start at cursor - overlap, got %v", f.since)
	}
	tn, _ = st.GetTenant(ctx, "t1")
	if got := tn.IdentityLogCursors[platform.ConnOkta]; !got.Equal(at.Add(5 * time.Minute)) {
		t.Errorf("an empty read must not move the cursor, got %v", got)
	}
}

// A failed read is NOT an empty window. The provider is named in Failed, ran is false when nothing
// was read, and the cursor does not move — so no event is skipped past.
func TestSyncIdentityLogs_FailedReadIsNotAnEmptyWindow(t *testing.T) {
	st := store.NewMemory()
	ctx := context.Background()
	_ = st.PutTenant(ctx, platform.Tenant{ID: "t1"})
	_ = st.PutConnection(ctx, platform.Connection{ID: "c1", TenantID: "t1", Kind: platform.ConnOkta, Status: platform.ConnActive, SecretRef: "sealed"})
	_ = st.PutConnection(ctx, platform.Connection{ID: "c2", TenantID: "t1", Kind: platform.ConnM365, Status: platform.ConnActive, SecretRef: "sealed"})
	svc := &Service{Store: st, Tokens: idTokens{tok: "tok"}, NewID: func() string { return "x" },
		IdentityLogFetchers: map[string]identitylog.Fetcher{
			platform.ConnOkta: &fakeLog{err: errors.New("403 okta.logs.read not granted")},
			platform.ConnM365: &fakeLog{err: errors.New("401")},
		}}
	res, ran := svc.SyncIdentityLogs(ctx, "t1")
	if ran {
		t.Fatal("nothing was read → ran must be false, or the pass would mark identitythreat covered")
	}
	if len(res.Failed) != 2 || res.Failed[platform.ConnOkta] == "" {
		t.Errorf("both failures must be named: %+v", res.Failed)
	}
	tn, _ := st.GetTenant(ctx, "t1")
	if len(tn.IdentityLogCursors) != 0 {
		t.Error("a failed read moved the cursor")
	}

	// A credential that cannot be opened is a named failure too, and an inactive connection is skipped.
	svc.Tokens = idTokens{}
	_ = st.PutConnection(ctx, platform.Connection{ID: "c2", TenantID: "t1", Kind: platform.ConnM365, Status: platform.ConnQuarantined, SecretRef: "sealed"})
	res, ran = svc.SyncIdentityLogs(ctx, "t1")
	if ran || res.Failed[platform.ConnOkta] != "credential could not be opened" || res.Failed[platform.ConnM365] != "" {
		t.Errorf("token failure must be named and the quarantined connection skipped: ran=%v failed=%+v", ran, res.Failed)
	}
}

// No fetchers wired (a deployment without the feature) → not ran, nothing stored, no panic.
func TestSyncIdentityLogs_UnwiredIsNotObserved(t *testing.T) {
	st := store.NewMemory()
	_ = st.PutTenant(context.Background(), platform.Tenant{ID: "t1"})
	svc := &Service{Store: st, Tokens: idTokens{tok: "t"}, NewID: func() string { return "x" }}
	if _, ran := svc.SyncIdentityLogs(context.Background(), "t1"); ran {
		t.Fatal("no fetchers → the log was not observed")
	}
}
