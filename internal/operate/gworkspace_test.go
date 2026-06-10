package operate

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestGWorkspace_FetchAssemblesWorkspace(t *testing.T) {
	page := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok-1" {
			t.Errorf("missing bearer token: %q", r.Header.Get("Authorization"))
		}
		w.Header().Set("Content-Type", "application/json")
		if page == 0 {
			page++
			// first page + a continuation token to exercise pagination
			_, _ = w.Write([]byte(`{"nextPageToken":"p2","users":[
				{"primaryEmail":"ceo@acme","isAdmin":true,"isEnrolledIn2Sv":false,"lastLoginTime":"2026-06-10T00:00:00.000Z"},
				{"primaryEmail":"gone@acme","isDelegatedAdmin":true,"suspended":true,"lastLoginTime":"1970-01-01T00:00:00.000Z"}
			]}`))
			return
		}
		_, _ = w.Write([]byte(`{"users":[
			{"primaryEmail":"stale@acme","isEnrolledIn2Sv":true,"lastLoginTime":"2026-01-01T00:00:00.000Z"}
		]}`))
	}))
	defer srv.Close()

	g := NewGWorkspace()
	g.APIBase = srv.URL
	now := time.Date(2026, 6, 11, 0, 0, 0, 0, time.UTC)

	ws, err := g.Fetch(context.Background(), "tok-1", now)
	if err != nil {
		t.Fatal(err)
	}
	if ws.Provider != "gworkspace" || len(ws.Users) != 3 {
		t.Fatalf("want 3 users across 2 pages, got %d: %+v", len(ws.Users), ws)
	}

	by := map[string]User{}
	for _, u := range ws.Users {
		by[u.Email] = u
	}
	// the super-admin without 2SV, recent login
	if u := by["ceo@acme"]; !u.SuperAdmin || u.MFA || u.LastLoginDays != 1 {
		t.Errorf("ceo mapped wrong: %+v", u)
	}
	// never-logged-in suspended delegated admin
	if u := by["gone@acme"]; !u.Admin || !u.Suspended || u.LastLoginDays < 99999 {
		t.Errorf("gone mapped wrong: %+v", u)
	}
	// stale-but-mfa user (~161 days)
	if u := by["stale@acme"]; !u.MFA || u.LastLoginDays < 150 {
		t.Errorf("stale mapped wrong: %+v", u)
	}
}

func TestGWorkspace_FetchFeedsAssessGrounded(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"users":[{"primaryEmail":"admin@acme","isAdmin":true,"isEnrolledIn2Sv":false,"lastLoginTime":"2026-06-10T00:00:00.000Z"}]}`))
	}))
	defer srv.Close()
	g := NewGWorkspace()
	g.APIBase = srv.URL
	ws, _ := g.Fetch(context.Background(), "t", time.Now())

	// the live snapshot flows straight into the grounded posture engine
	fs := Assess(ws, Options{})
	if len(fs) != 1 || fs[0].RuleID != "operate::admin-without-mfa" || fs[0].Endpoint != "admin@acme" {
		t.Fatalf("live fetch → grounded finding failed: %+v", fs)
	}
}

func TestGWorkspace_HTTPErrorSurfaces(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()
	g := NewGWorkspace()
	g.APIBase = srv.URL
	if _, err := g.Fetch(context.Background(), "t", time.Now()); err == nil {
		t.Error("a 403 from the directory API should surface as an error")
	}
}
