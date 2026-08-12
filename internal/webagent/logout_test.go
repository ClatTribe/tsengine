package webagent

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The predicate in isolation — the FP-free part. Only "present before AND after" grounds.
func TestSessionInvalidationFailed_Predicate(t *testing.T) {
	priv := &Resp{Status: 200, Body: "email: victim@corp.example"}
	gone := &Resp{Status: 200, Body: "please log in"}
	for _, c := range []struct {
		name          string
		before, after *Resp
		marker        string
		want          bool
	}{
		{"survived logout (VULN)", priv, priv, "victim@corp.example", true},
		{"invalidated (SECURE)", priv, gone, "victim@corp.example", false},
		{"never had it (bad marker)", gone, priv, "victim@corp.example", false},
		{"marker too short", priv, priv, "a@b", false},
		{"nil after", priv, nil, "victim@corp.example", false},
	} {
		if got := sessionInvalidationFailed(c.before, c.after, c.marker); got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}

// A server whose logout does NOT invalidate the session must produce a session_invalidation_failed
// turn; a server that DOES invalidate must not. This is the whole point — telling those two apart.
func TestLogoutProbe_EndToEnd(t *testing.T) {
	// VULNERABLE: the cookie is honoured forever; /logout is cosmetic, so the marker survives it.
	vuln := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sess, _ := r.Cookie("sess")
		if r.URL.Path == "/account" && sess != nil && sess.Value == "live" {
			fmt.Fprint(w, "<p>email: victim@corp.example</p>")
			return
		}
		if r.URL.Path == "/logout" {
			fmt.Fprint(w, "bye") // does NOT clear or revoke the session
			return
		}
		fmt.Fprint(w, "please log in")
	}))
	defer vuln.Close()

	cc := &Context{Target: vuln.URL, ctx: context.Background()}
	cc.req = NewRequester([]string{hostOf(vuln.URL)}, 40, 0)
	out := tLogoutProbe(cc, map[string]any{
		"protected_url":  vuln.URL + "/account",
		"logout_url":     vuln.URL + "/logout",
		"session_cookie": "sess=live",
		"marker":         "victim@corp.example",
	})
	if len(cc.History) == 0 || !hasIndicator(cc.History[len(cc.History)-1], "session_invalidation_failed") {
		t.Errorf("vulnerable server did not set session_invalidation_failed: %s", out)
	}

	// SECURE: /logout revokes the session id, so the marker is gone on the re-read.
	revoked := map[string]bool{}
	secure := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sess, _ := r.Cookie("sess")
		valid := sess != nil && sess.Value == "live" && !revoked[sess.Value]
		if r.URL.Path == "/account" && valid {
			fmt.Fprint(w, "<p>email: victim@corp.example</p>")
			return
		}
		if r.URL.Path == "/logout" {
			if sess != nil {
				revoked[sess.Value] = true
			}
			fmt.Fprint(w, "logged out")
			return
		}
		fmt.Fprint(w, "please log in")
	}))
	defer secure.Close()

	cc2 := &Context{Target: secure.URL, ctx: context.Background()}
	cc2.req = NewRequester([]string{hostOf(secure.URL)}, 40, 0)
	out2 := tLogoutProbe(cc2, map[string]any{
		"protected_url":  secure.URL + "/account",
		"logout_url":     secure.URL + "/logout",
		"session_cookie": "sess=live",
		"marker":         "victim@corp.example",
	})
	if len(cc2.History) > 0 && hasIndicator(cc2.History[len(cc2.History)-1], "session_invalidation_failed") {
		t.Errorf("SECURE server (logout actually revokes) was flagged — false positive: %s", out2)
	}
}

// The class is grounded — record_finding must accept broken_session_management once the indicator fires,
// and reject it without.
func TestLogoutProbe_ClassIsGrounded(t *testing.T) {
	inds, ok := requiredIndicator["broken_session_management"]
	if !ok {
		t.Fatal("broken_session_management is not a grounded class")
	}
	found := false
	for _, i := range inds {
		if i == "session_invalidation_failed" {
			found = true
		}
	}
	if !found {
		t.Errorf("broken_session_management does not require session_invalidation_failed: %v", inds)
	}
}

// Missing args are corrected, not fatal.
func TestLogoutProbe_MissingArgs(t *testing.T) {
	cc := &Context{ctx: context.Background()}
	cc.req = NewRequester([]string{"x"}, 5, 0)
	if out := tLogoutProbe(cc, map[string]any{"protected_url": "http://x/a"}); !strings.Contains(out, "ERROR") {
		t.Errorf("missing args should return an actionable ERROR, got: %s", out)
	}
}
