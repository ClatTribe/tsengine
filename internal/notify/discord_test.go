package notify

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ClatTribe/tsengine/pkg/platform"
)

func TestDiscord_PostsEmbedForHighSeverity(t *testing.T) {
	var body []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ = readAll(r)
		w.WriteHeader(http.StatusNoContent) // Discord's success code
	}))
	defer srv.Close()

	d := NewDiscord(srv.URL)
	d.HTTP = srv.Client()
	inc := platform.Incident{
		ID: "inc-1", TenantID: "t1", RuleID: "nuclei::sqli", Title: "SQL injection",
		Severity: "critical", FindingID: "f-1", OpenedAt: time.Now(),
	}
	if err := d.IncidentOpened(context.Background(), inc); err != nil {
		t.Fatalf("IncidentOpened: %v", err)
	}
	var got struct {
		Embeds []struct {
			Title       string `json:"title"`
			Description string `json:"description"`
			Color       int    `json:"color"`
			Fields      []struct {
				Name, Value string
			} `json:"fields"`
		} `json:"embeds"`
	}
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("payload not JSON: %v", err)
	}
	if len(got.Embeds) != 1 {
		t.Fatalf("want 1 embed, got %d", len(got.Embeds))
	}
	e := got.Embeds[0]
	if e.Description != "SQL injection" || e.Color != 0xB00020 || len(e.Fields) != 3 {
		t.Errorf("embed wrong: %+v", e)
	}
}

func TestDiscord_HighGateSkipsLow(t *testing.T) {
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { called = true; w.WriteHeader(204) }))
	defer srv.Close()
	d := NewDiscord(srv.URL)
	d.HTTP = srv.Client()
	if err := d.IncidentOpened(context.Background(), platform.Incident{Severity: "low", OpenedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if called {
		t.Error("default gate must skip a low-severity incident")
	}
	// MinSeverity=all sends it
	d.MinSeverity = "all"
	if err := d.IncidentOpened(context.Background(), platform.Incident{Severity: "low", Title: "x", OpenedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Error("MinSeverity=all should send a low-severity incident")
	}
}

func TestDiscord_EmptyURLIsNoop(t *testing.T) {
	d := NewDiscord("")
	if err := d.IncidentOpened(context.Background(), platform.Incident{Severity: "critical"}); err != nil {
		t.Errorf("empty URL must be a no-op, got %v", err)
	}
}
