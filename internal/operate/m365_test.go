package operate

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestM365_FetchMergesUsersAndRegistration(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok" {
			t.Errorf("missing bearer: %q", r.Header.Get("Authorization"))
		}
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.Contains(r.URL.Path, "/users"):
			_, _ = w.Write([]byte(`{"value":[
				{"userPrincipalName":"ceo@acme","accountEnabled":true,"signInActivity":{"lastSignInDateTime":"2026-06-10T00:00:00Z"}},
				{"userPrincipalName":"gone@acme","accountEnabled":false,"signInActivity":{"lastSignInDateTime":"2025-01-01T00:00:00Z"}}
			]}`))
		case strings.Contains(r.URL.Path, "userRegistrationDetails"):
			_, _ = w.Write([]byte(`{"value":[
				{"userPrincipalName":"ceo@acme","isMfaRegistered":false,"isAdmin":true},
				{"userPrincipalName":"gone@acme","isMfaRegistered":true,"isAdmin":false}
			]}`))
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
		}
	}))
	defer srv.Close()

	m := NewM365()
	m.APIBase = srv.URL
	now := time.Date(2026, 6, 11, 0, 0, 0, 0, time.UTC)
	ws, err := m.Fetch(context.Background(), "tok", now)
	if err != nil {
		t.Fatal(err)
	}
	if ws.Provider != "m365" || len(ws.Users) != 2 {
		t.Fatalf("want 2 merged users, got %d: %+v", len(ws.Users), ws)
	}
	by := map[string]User{}
	for _, u := range ws.Users {
		by[u.Email] = u
	}
	// the admin's MFA (from the registration report) + enabled+stale (from /users) merged
	if u := by["ceo@acme"]; !u.Admin || u.MFA || u.Suspended || u.LastLoginDays != 1 {
		t.Errorf("ceo merge wrong: %+v", u)
	}
	if u := by["gone@acme"]; !u.Suspended || !u.MFA {
		t.Errorf("gone merge wrong: %+v", u)
	}

	// the merged snapshot drives the grounded engine to the admin-without-mfa critical
	fs := Assess(ws, Options{})
	var crit bool
	for _, f := range fs {
		if f.RuleID == "operate::admin-without-mfa" && f.Endpoint == "ceo@acme" {
			crit = true
		}
	}
	if !crit {
		t.Errorf("expected admin-without-mfa for ceo@acme from the merged M365 snapshot: %+v", fs)
	}
}

func TestM365_PaginationFollowed(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.Contains(r.URL.Path, "/users") && r.URL.Query().Get("page") == "":
			_, _ = w.Write([]byte(`{"@odata.nextLink":"` + srv.URL + `/v1.0/users?page=2","value":[{"userPrincipalName":"a@x","accountEnabled":true,"signInActivity":{"lastSignInDateTime":"2026-06-01T00:00:00Z"}}]}`))
		case strings.Contains(r.URL.Path, "/users"):
			_, _ = w.Write([]byte(`{"value":[{"userPrincipalName":"b@x","accountEnabled":true,"signInActivity":{"lastSignInDateTime":"2026-06-01T00:00:00Z"}}]}`))
		default: // registration report, single page
			_, _ = w.Write([]byte(`{"value":[]}`))
		}
	}))
	defer srv.Close()
	m := NewM365()
	m.APIBase = srv.URL
	ws, err := m.Fetch(context.Background(), "tok", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(ws.Users) != 2 {
		t.Errorf("pagination not followed: want 2 users across pages, got %d", len(ws.Users))
	}
}

func TestM365_HTTPErrorSurfaces(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()
	m := NewM365()
	m.APIBase = srv.URL
	if _, err := m.Fetch(context.Background(), "tok", time.Now()); err == nil {
		t.Error("a 401 from Graph should surface as an error")
	}
}
