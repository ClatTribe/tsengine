package platformapi

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

func seedLiveState(t *testing.T, st interface {
	PutFinding(context.Context, string, types.Finding) error
	PutIncident(context.Context, platform.Incident) error
	PutAction(context.Context, platform.Action) error
}) {
	t.Helper()
	ctx := context.Background()
	if err := st.PutFinding(ctx, "t1", types.Finding{ID: "f-h", Severity: types.SeverityHigh}); err != nil {
		t.Fatal(err)
	}
	if err := st.PutFinding(ctx, "t1", types.Finding{ID: "f-l", Severity: types.SeverityLow}); err != nil {
		t.Fatal(err)
	}
	if err := st.PutIncident(ctx, platform.Incident{ID: "i1", TenantID: "t1", Status: platform.IncidentOpen}); err != nil {
		t.Fatal(err)
	}
	if err := st.PutAction(ctx, platform.Action{ID: "act1", TenantID: "t1", Tier: 2, Status: platform.ActPendingApproval}); err != nil {
		t.Fatal(err)
	}
}

func TestTenantSnapshot_Counts(t *testing.T) {
	_, st := setup(t)
	seedLiveState(t, st)

	snap, err := tenantSnapshot(context.Background(), st, "t1")
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	if snap.Findings != 2 || snap.Severity["high"] != 1 || snap.Severity["low"] != 1 {
		t.Errorf("findings/severity wrong: %+v", snap)
	}
	if snap.OpenIncidents != 1 {
		t.Errorf("open incidents: want 1, got %d", snap.OpenIncidents)
	}
	if snap.PendingApprovals != 1 {
		t.Errorf("pending approvals: want 1, got %d", snap.PendingApprovals)
	}

	// tenant isolation: t2 sees an empty snapshot
	other, _ := tenantSnapshot(context.Background(), st, "t2")
	if other.Findings != 0 || other.OpenIncidents != 0 || other.PendingApprovals != 0 {
		t.Errorf("ISOLATION: t2 snapshot should be empty, got %+v", other)
	}
}

func TestEvents_StreamsInitialState(t *testing.T) {
	h, st := setup(t)
	seedLiveState(t, st)
	t.Setenv("TSENGINE_SSE_INTERVAL", "10s") // long enough that only the initial emit fires

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	req := httptest.NewRequest("GET", "/v1/events", nil).WithContext(ctx)
	req.Header.Set("Authorization", "Bearer platform-tok")
	req.Header.Set("X-Tenant-ID", "t1")
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req) // blocks until the request context times out

	if ct := rec.Header().Get("Content-Type"); ct != "text/event-stream" {
		t.Fatalf("content-type: want text/event-stream, got %q", ct)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "event: state") {
		t.Fatalf("no state event in stream: %q", body)
	}
	if !strings.Contains(body, `"pending_approvals":1`) || !strings.Contains(body, `"open_incidents":1`) {
		t.Errorf("stream missing live counts: %q", body)
	}
}
