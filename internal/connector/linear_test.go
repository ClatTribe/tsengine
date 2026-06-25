package connector

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/pkg/platform"
)

func TestLinear_FileTicketCreatesIssue(t *testing.T) {
	var gotAuth string
	var gotVars map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		var body struct {
			Query     string         `json:"query"`
			Variables map[string]any `json:"variables"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		gotVars = body.Variables
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"issueCreate":{"success":true}}}`))
	}))
	defer srv.Close()

	l := NewLinear("lin_api_key", "team-123")
	l.BaseURL = srv.URL
	act := platform.Action{FindingID: "f-1", Title: "MFA not enforced for admin", Payload: map[string]any{"summary": "Enable MFA enforcement."}}
	if err := l.FileTicket(context.Background(), act); err != nil {
		t.Fatalf("FileTicket: %v", err)
	}
	if gotAuth != "lin_api_key" { // personal key goes raw, no Bearer
		t.Errorf("auth header = %q, want raw API key", gotAuth)
	}
	input, _ := gotVars["input"].(map[string]any)
	if input["teamId"] != "team-123" || input["title"] != "MFA not enforced for admin" || input["description"] != "Enable MFA enforcement." {
		t.Errorf("issue input wrong: %+v", input)
	}
}

func TestLinear_SurfacesGraphQLErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// GraphQL: HTTP 200 but a logical error in the body.
		_, _ = w.Write([]byte(`{"errors":[{"message":"Team not found"}]}`))
	}))
	defer srv.Close()
	l := NewLinear("k", "bad-team")
	l.BaseURL = srv.URL
	err := l.FileTicket(context.Background(), platform.Action{Title: "x"})
	if err == nil || !strings.Contains(err.Error(), "Team not found") {
		t.Errorf("want the GraphQL error surfaced, got %v", err)
	}
}

func TestLinear_NotConfigured(t *testing.T) {
	if err := (&Linear{}).FileTicket(context.Background(), platform.Action{}); err == nil {
		t.Error("missing API key + team id must error, not silently succeed")
	}
	if err := NewLinear("key", "").FileTicket(context.Background(), platform.Action{}); err == nil {
		t.Error("missing team id must error")
	}
}
