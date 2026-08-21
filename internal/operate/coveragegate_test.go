package operate

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// gwsServer serves a one-page user directory and answers the per-user tokens endpoint
// with tokensStatus, so a test can make the grant read fail exactly as a missing scope
// does (403) while the directory read succeeds.
func gwsServer(t *testing.T, tokensStatus int, tokensBody string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(r.URL.Path, "/tokens") {
			if tokensStatus != http.StatusOK {
				w.WriteHeader(tokensStatus)
				_, _ = w.Write([]byte(`{"error":"insufficient scope"}`))
				return
			}
			_, _ = w.Write([]byte(tokensBody))
			return
		}
		_, _ = w.Write([]byte(`{"users":[{"primaryEmail":"a@acme","isEnrolledIn2Sv":true,"lastLoginTime":"2026-06-10T00:00:00.000Z"}]}`))
	}))
}

// A 403 on every token lookup is the missing-scope case, and it is the one that must not
// pass as a clean OAuth posture. fetchGrants swallows per-user errors on purpose — one
// user's failure must not lose everyone else's apps — which is exactly why the total
// failure needs counting rather than inferring from the empty result.
func TestGWorkspace_TotalGrantFailureIsDeclared(t *testing.T) {
	srv := gwsServer(t, http.StatusForbidden, "")
	defer srv.Close()
	g := NewGWorkspace()
	g.APIBase = srv.URL

	ws, err := g.Fetch(context.Background(), "tok", time.Date(2026, 6, 11, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("a failed grant read must not fail the posture fetch: %v", err)
	}
	if len(ws.OAuthGrants) != 0 {
		t.Fatalf("premise changed: a 403 should yield no grants, got %+v", ws.OAuthGrants)
	}
	if !contains(ws.Unavailable, "oauth_grants") {
		t.Error("every grant lookup failed and nothing recorded it — the scan will report a clean OAuth posture for apps it never saw")
	}
	// A failed read means no app review happened, so the provider limit is NOT the story.
	if contains(ws.ProviderLimits, "oauth_publisher_verification") {
		t.Error("a failed read must not also claim a provider limit — the customer would be told to stop looking")
	}
}

// A successful read declares the provider limit instead: Google's tokens API exposes
// scopes but not publisher verification, so the unverified-app check cannot run at all.
func TestGWorkspace_SuccessfulReadDeclaresTheProviderLimit(t *testing.T) {
	srv := gwsServer(t, http.StatusOK, `{"items":[{"clientId":"app-1","displayText":"Some App","scopes":["https://www.googleapis.com/auth/drive"]}]}`)
	defer srv.Close()
	g := NewGWorkspace()
	g.APIBase = srv.URL

	ws, err := g.Fetch(context.Background(), "tok", time.Date(2026, 6, 11, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if len(ws.OAuthGrants) == 0 {
		t.Fatal("premise changed: the grant read should have succeeded")
	}
	if contains(ws.Unavailable, "oauth_grants") {
		t.Error("a successful read must not be reported as unavailable")
	}
	// The limit is RECORDED on the workspace (it is a real fact worth carrying) but is not
	// emitted as a per-scan finding — see TestCoverageGaps_ProviderLimitIsNotAPerScanFinding.
	if !contains(ws.ProviderLimits, "oauth_publisher_verification") {
		t.Error("Google cannot report publisher verification, and the fetcher must record it even though it is not emitted per scan")
	}
	for _, f := range Assess(ws, Options{Now: time.Unix(0, 0)}) {
		if strings.Contains(f.RuleID, "publisher-verification") {
			t.Errorf("a standing provider limit leaked into the per-scan findings: %s", f.RuleID)
		}
	}
}

func contains(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}
