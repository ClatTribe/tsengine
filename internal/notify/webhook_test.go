package notify

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ClatTribe/tsengine/pkg/platform"
)

func TestWebhook_DeliversSignedEvent(t *testing.T) {
	var gotBody []byte
	var gotSig, gotType, gotCT string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotBody, _ = readAll(r)
		gotSig = r.Header.Get("X-TensorShield-Signature")
		gotType = r.Header.Get("X-TensorShield-Event")
		gotCT = r.Header.Get("Content-Type")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	wh := NewWebhook(srv.URL, "shh-secret")
	wh.HTTP = srv.Client()
	inc := platform.Incident{
		ID: "inc-1", TenantID: "ten-1", Key: "nuclei::sqli|/x", RuleID: "nuclei::sqli",
		Title: "SQL injection", Severity: "critical", FindingID: "f-1", Attacked: true,
		OpenedAt: time.Date(2026, 6, 22, 10, 0, 0, 0, time.UTC),
	}
	if err := wh.IncidentOpened(context.Background(), inc); err != nil {
		t.Fatalf("IncidentOpened: %v", err)
	}

	// Content-type + event header.
	if !strings.Contains(gotCT, "application/json") {
		t.Errorf("content-type = %q", gotCT)
	}
	if gotType != "incident.opened" {
		t.Errorf("event header = %q", gotType)
	}
	// The signature must verify against the EXACT raw body (the receiver's check).
	if want := "sha256=" + Sign("shh-secret", gotBody); gotSig != want {
		t.Errorf("signature mismatch: got %q want %q", gotSig, want)
	}
	// Payload carries the grounded incident data.
	var ev WebhookEvent
	if err := json.Unmarshal(gotBody, &ev); err != nil {
		t.Fatalf("payload not JSON: %v", err)
	}
	if ev.Version != "1" || ev.Type != "incident.opened" || ev.Tenant != "ten-1" ||
		ev.IncidentID != "inc-1" || ev.RuleID != "nuclei::sqli" || ev.Severity != "critical" ||
		ev.FindingID != "f-1" || !ev.Attacked {
		t.Errorf("payload wrong: %+v", ev)
	}
}

func TestWebhook_NoSecretOmitsSignature(t *testing.T) {
	var sigSeen string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sigSeen = r.Header.Get("X-TensorShield-Signature")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	wh := NewWebhook(srv.URL, "") // no secret
	wh.HTTP = srv.Client()
	if err := wh.IncidentOpened(context.Background(), platform.Incident{ID: "i", Severity: "low", OpenedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if sigSeen != "" {
		t.Errorf("no secret → no signature header, got %q", sigSeen)
	}
}

func TestWebhook_EmptyURLIsNoop(t *testing.T) {
	wh := NewWebhook("", "x") // empty URL → must not panic / call anything
	if err := wh.IncidentOpened(context.Background(), platform.Incident{Severity: "critical"}); err != nil {
		t.Errorf("empty URL must be a no-op, got %v", err)
	}
}

func TestWebhook_HighGateSkipsLowSeverity(t *testing.T) {
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { called = true; w.WriteHeader(200) }))
	defer srv.Close()
	wh := NewWebhook(srv.URL, "")
	wh.HTTP = srv.Client()
	wh.MinSeverity = "high"
	if err := wh.IncidentOpened(context.Background(), platform.Incident{Severity: "low", OpenedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if called {
		t.Error("MinSeverity=high must skip a low-severity incident")
	}
}

func readAll(r *http.Request) ([]byte, error) {
	defer r.Body.Close()
	buf := make([]byte, 0, 512)
	tmp := make([]byte, 512)
	for {
		n, err := r.Body.Read(tmp)
		buf = append(buf, tmp[:n]...)
		if err != nil {
			if err.Error() == "EOF" {
				return buf, nil
			}
			return buf, nil
		}
	}
}
