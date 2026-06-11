package operate

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// oktaFake serves a 2-page user list plus per-user factors + roles, exercising
// pagination, MFA detection, admin-role detection, and the active/suspended split.
func oktaFake(t *testing.T) *httptest.Server {
	t.Helper()
	var base string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok" {
			t.Errorf("missing bearer, got %q", r.Header.Get("Authorization"))
		}
		w.Header().Set("Content-Type", "application/json")
		switch {
		// page 1 of users → Link to page 2
		case r.URL.Path == "/api/v1/users" && r.URL.Query().Get("after") == "":
			w.Header().Set("Link", `<`+base+`/api/v1/users?after=p2>; rel="next"`)
			_, _ = w.Write([]byte(`[
				{"id":"u1","status":"ACTIVE","lastLogin":"2026-06-09T00:00:00Z","profile":{"email":"admin@acme.com"}},
				{"id":"u2","status":"ACTIVE","lastLogin":"2026-06-09T00:00:00Z","profile":{"email":"alice@acme.com"}}
			]`))
		case r.URL.Path == "/api/v1/users" && r.URL.Query().Get("after") == "p2":
			_, _ = w.Write([]byte(`[
				{"id":"u3","status":"SUSPENDED","lastLogin":"2024-01-01T00:00:00Z","profile":{"email":"gone@acme.com"}}
			]`))
		// u1 is a super-admin with NO active factor → the critical "admin-without-mfa".
		case r.URL.Path == "/api/v1/users/u1/factors":
			_, _ = w.Write([]byte(`[{"factorType":"sms","status":"PENDING_ACTIVATION"}]`))
		case r.URL.Path == "/api/v1/users/u1/roles":
			_, _ = w.Write([]byte(`[{"type":"SUPER_ADMIN"}]`))
		// u2 is a normal user with an active factor.
		case r.URL.Path == "/api/v1/users/u2/factors":
			_, _ = w.Write([]byte(`[{"factorType":"push","status":"ACTIVE"}]`))
		case r.URL.Path == "/api/v1/users/u2/roles":
			_, _ = w.Write([]byte(`[]`))
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	base = srv.URL
	t.Cleanup(srv.Close)
	return srv
}

func TestOkta_FetchUsersFactorsRoles(t *testing.T) {
	srv := oktaFake(t)
	o := &Okta{OrgURL: srv.URL, HTTP: srv.Client()}
	ws, err := o.Fetch(context.Background(), "tok", time.Date(2026, 6, 10, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if ws.Provider != "okta" {
		t.Errorf("provider = %q", ws.Provider)
	}
	if len(ws.Users) != 3 { // pagination merged both pages
		t.Fatalf("want 3 users across 2 pages, got %d", len(ws.Users))
	}
	byEmail := map[string]User{}
	for _, u := range ws.Users {
		byEmail[u.Email] = u
	}
	// u1: active super-admin, no active factor → SuperAdmin && !MFA (the critical case).
	if u := byEmail["admin@acme.com"]; !u.SuperAdmin || u.MFA || u.Suspended {
		t.Errorf("admin@acme.com should be active super-admin without MFA, got %+v", u)
	}
	// u2: active normal user with an active factor.
	if u := byEmail["alice@acme.com"]; u.Admin || u.SuperAdmin || !u.MFA {
		t.Errorf("alice@acme.com should be an MFA-enrolled non-admin, got %+v", u)
	}
	// u3: suspended → no MFA/role calls, flagged suspended (excluded from active checks).
	if u := byEmail["gone@acme.com"]; !u.Suspended {
		t.Errorf("gone@acme.com should be suspended, got %+v", u)
	}
}

// The fetched workspace must drive the real posture checks: the admin-without-MFA case
// is the highest-severity operate finding.
func TestOkta_FetchFeedsPostureChecks(t *testing.T) {
	srv := oktaFake(t)
	o := &Okta{OrgURL: srv.URL, HTTP: srv.Client()}
	ws, err := o.Fetch(context.Background(), "tok", time.Date(2026, 6, 10, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	var sawAdminNoMFA bool
	for _, f := range Assess(ws, Options{}) {
		if f.RuleID == "operate::admin-without-mfa" {
			sawAdminNoMFA = true
		}
	}
	if !sawAdminNoMFA {
		t.Fatal("an active super-admin without MFA should produce operate::admin-without-mfa")
	}
}

func TestNextLink(t *testing.T) {
	cases := map[string]string{
		`<https://x.okta.com/api/v1/users?after=abc>; rel="next"`:                    "https://x.okta.com/api/v1/users?after=abc",
		`<https://x/self>; rel="self", <https://x/api/v1/users?after=z>; rel="next"`: "https://x/api/v1/users?after=z",
		`<https://x/self>; rel="self"`:                                               "",
		``:                                                                           "",
	}
	for hdr, want := range cases {
		var in []string
		if hdr != "" {
			in = []string{hdr}
		}
		if got := nextLink(in); got != want {
			t.Errorf("nextLink(%q) = %q, want %q", hdr, got, want)
		}
	}
}
