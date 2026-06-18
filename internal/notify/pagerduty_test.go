package notify

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ClatTribe/tsengine/pkg/platform"
)

func TestPagerDuty_PagesCriticalWithTriggerPayload(t *testing.T) {
	var got map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&got)
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"status":"success"}`))
	}))
	defer srv.Close()

	p := &PagerDuty{RoutingKey: "RK123", EventsURL: srv.URL, HTTP: srv.Client()}
	inc := platform.Incident{ID: "i-1", TenantID: "t1", Severity: "critical", Title: "Public S3 bucket", RuleID: "prowler::s3-public", FindingID: "f-9"}
	if err := p.IncidentOpened(context.Background(), inc); err != nil {
		t.Fatalf("page: %v", err)
	}
	if got["routing_key"] != "RK123" || got["event_action"] != "trigger" || got["dedup_key"] != "i-1" {
		t.Errorf("trigger envelope wrong: %v", got)
	}
	payload, _ := got["payload"].(map[string]any)
	if payload["severity"] != "critical" {
		t.Errorf("severity map: want critical, got %v", payload["severity"])
	}
	if payload["summary"] == nil || payload["source"] != "tsengine" {
		t.Errorf("payload incomplete: %v", payload)
	}
}

func TestPagerDuty_DoesNotPageBelowThreshold(t *testing.T) {
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	p := &PagerDuty{RoutingKey: "RK", EventsURL: srv.URL, HTTP: srv.Client()}
	for _, sev := range []string{"medium", "low", "info"} {
		if err := p.IncidentOpened(context.Background(), platform.Incident{ID: "x", Severity: sev}); err != nil {
			t.Fatalf("%s: %v", sev, err)
		}
	}
	if called {
		t.Error("below-threshold incidents must NOT page")
	}
}

func TestPagerDuty_NoRoutingKeyIsNoop(t *testing.T) {
	p := &PagerDuty{} // unconfigured
	if err := p.IncidentOpened(context.Background(), platform.Incident{Severity: "critical"}); err != nil {
		t.Errorf("unconfigured PagerDuty should be a graceful no-op, got %v", err)
	}
}

func TestMultiAlerter_FansOutBestEffort(t *testing.T) {
	var a, b int
	inc := platform.Incident{Severity: "high"}
	m := MultiAlerter{
		fakeAlerter(func() error { a++; return assertErr }),
		nil, // skipped
		fakeAlerter(func() error { b++; return nil }),
	}
	if err := m.IncidentOpened(context.Background(), inc); err == nil {
		t.Error("want the first child's error surfaced")
	}
	if a != 1 || b != 1 {
		t.Errorf("both children should fire despite one erroring: a=%d b=%d", a, b)
	}
}

type fakeAlerter func() error

func (f fakeAlerter) IncidentOpened(context.Context, platform.Incident) error { return f() }

var assertErr = &alertErr{}

type alertErr struct{}

func (*alertErr) Error() string { return "boom" }
