package notify

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/pkg/platform"
)

func TestTeams_PostsCardForHighIncident(t *testing.T) {
	var gotBody string
	var gotContentType string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		gotContentType = r.Header.Get("Content-Type")
		w.WriteHeader(200)
		_, _ = w.Write([]byte("1"))
	}))
	defer srv.Close()

	tm := &Teams{WebhookURL: srv.URL, HTTP: srv.Client()}
	inc := platform.Incident{ID: "i-1", TenantID: "t1", Severity: "high", Title: "Malicious dependency: ua-parser-js", RuleID: "malicious-packages::ua-parser-js", FindingID: "f-9"}
	if err := tm.IncidentOpened(context.Background(), inc); err != nil {
		t.Fatalf("IncidentOpened: %v", err)
	}
	if gotContentType != "application/json" {
		t.Errorf("content-type = %q", gotContentType)
	}
	// Valid MessageCard carrying the incident facts.
	var card map[string]any
	if err := json.Unmarshal([]byte(gotBody), &card); err != nil {
		t.Fatalf("body is not JSON: %v\n%s", err, gotBody)
	}
	if card["@type"] != "MessageCard" {
		t.Errorf("not a MessageCard: %v", card["@type"])
	}
	for _, want := range []string{"ua-parser-js", "malicious-packages::ua-parser-js", "high", "t1"} {
		if !strings.Contains(gotBody, want) {
			t.Errorf("card missing %q", want)
		}
	}
}

func TestTeams_GatesBelowThreshold(t *testing.T) {
	posted := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		posted = true
		w.WriteHeader(200)
	}))
	defer srv.Close()

	tm := &Teams{WebhookURL: srv.URL, HTTP: srv.Client()}
	for _, sev := range []string{"info", "low", "medium"} {
		if err := tm.IncidentOpened(context.Background(), platform.Incident{ID: "x", Severity: sev}); err != nil {
			t.Errorf("%s: %v", sev, err)
		}
	}
	if posted {
		t.Error("Teams should not post below high by default")
	}

	// MinSeverity=all posts everything.
	tm.MinSeverity = "all"
	if err := tm.IncidentOpened(context.Background(), platform.Incident{ID: "y", Severity: "low"}); err != nil {
		t.Errorf("MinSeverity=all low: %v", err)
	}
	if !posted {
		t.Error("MinSeverity=all should post a low incident")
	}
}

func TestTeams_NilAndEmptyAreNoops(t *testing.T) {
	var tm *Teams
	if err := tm.IncidentOpened(context.Background(), platform.Incident{Severity: "critical"}); err != nil {
		t.Errorf("nil Teams should be a no-op: %v", err)
	}
	if err := (&Teams{}).IncidentOpened(context.Background(), platform.Incident{Severity: "critical"}); err != nil {
		t.Errorf("empty webhook should be a no-op: %v", err)
	}
}

// Teams composes into MultiAlerter alongside the other alerters.
func TestTeams_ComposesIntoMultiAlerter(t *testing.T) {
	hit := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { hit++; w.WriteHeader(200) }))
	defer srv.Close()
	m := MultiAlerter{&Teams{WebhookURL: srv.URL, HTTP: srv.Client()}}
	if err := m.IncidentOpened(context.Background(), platform.Incident{Severity: "critical", Title: "x"}); err != nil {
		t.Fatalf("multi: %v", err)
	}
	if hit != 1 {
		t.Errorf("Teams alerter not invoked via MultiAlerter (hit=%d)", hit)
	}
}
