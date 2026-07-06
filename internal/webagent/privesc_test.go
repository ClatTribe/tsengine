package webagent

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestPrivescConfirmed_Predicate: self-privilege-escalation / mass-assignment is grounded by an
// OBSERVED state transition of the SAME session's own privilege — never asserted. It fires ONLY when
// a privilege marker is ABSENT in the session's baseline read and PRESENT after it made a call that
// granted it. The before/after differential on the same page auto-excludes a marker that was static
// all along (nav chrome, a footer), so it is false-positive-free without any policy declaration —
// which is exactly why it grounds the FP-free SUBSET of BFLA (self-escalation) that general
// function-level authz (an unprovable "this function is privileged" policy fact) cannot.
func TestPrivescConfirmed_Predicate(t *testing.T) {
	mk := func(status int, body string) *Resp { return &Resp{Status: status, Body: body} }
	cases := []struct {
		name          string
		before, after *Resp
		roleAfter     string
		want          bool
	}{
		{"self-escalation", mk(200, "user=alice role=user"), mk(200, "user=alice role=admin"), "role=admin", true},
		{"secure app ignores role (no change) NOT privesc", mk(200, "role=user"), mk(200, "role=user"), "role=admin", false},
		{"marker static in baseline (nav chrome) NOT privesc", mk(200, "Admin Panel link role=user"), mk(200, "Admin Panel link role=user"), "Admin Panel", false},
		{"baseline read failed NOT grounded", mk(403, ""), mk(200, "role=admin"), "role=admin", false},
		{"post-read failed NOT grounded", mk(200, "role=user"), mk(500, ""), "role=admin", false},
		{"empty marker ungrounded", mk(200, "a"), mk(200, "b"), "", false},
	}
	for _, c := range cases {
		if got := privescConfirmed(c.before, c.after, c.roleAfter); got != c.want {
			t.Errorf("%s: privescConfirmed = %v, want %v", c.name, got, c.want)
		}
	}
}

// TestPrivescProbe_EndToEnd: a mass-assignable role field (any user can POST role=admin and promote
// themselves) must produce a `privesc_confirmed` turn recordable as class=mass_assignment; a secure
// server that ignores the role field for non-admins must NOT.
func TestPrivescProbe_EndToEnd(t *testing.T) {
	// Vulnerable server: /me reflects the session's role; POST /profile mass-assigns role from the body.
	roles := map[string]string{"alice": "user"}
	vuln := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sess, _ := r.Cookie("sess")
		if sess == nil {
			w.WriteHeader(401)
			return
		}
		switch r.URL.Path {
		case "/me":
			fmt.Fprintf(w, "user=%s role=%s", sess.Value, roles[sess.Value])
		case "/profile":
			var body map[string]string
			_ = json.NewDecoder(r.Body).Decode(&body)
			if v := body["role"]; v != "" {
				roles[sess.Value] = v // MASS ASSIGNMENT: role is set straight from the request body
			}
			fmt.Fprint(w, "updated")
		}
	}))
	defer vuln.Close()

	cc := &Context{Target: vuln.URL, ctx: context.Background()}
	cc.req = NewRequester([]string{hostOf(vuln.URL)}, 40, 0)
	tPrivescProbe(cc, map[string]any{
		"session_cookie": "sess=alice",
		"verify_url":     vuln.URL + "/me",
		"role_after":     "role=admin",
		"escalate":       map[string]any{"method": "POST", "url": vuln.URL + "/profile", "body": map[string]any{"role": "admin"}},
	})
	if len(cc.History) == 0 || !hasIndicator(cc.History[len(cc.History)-1], "privesc_confirmed") {
		t.Fatalf("mass-assignment privesc did not fire privesc_confirmed: %+v", cc.History)
	}
	tid := cc.History[len(cc.History)-1].ID
	rec := tRecord(cc, map[string]any{
		"route": "/profile", "class": "mass_assignment", "evidence": []any{tid},
		"severity": "high", "rationale": "role is mass-assignable; a normal user self-promotes to admin",
	})
	if strings.Contains(rec, "REJECTED") {
		t.Fatalf("mass_assignment finding rejected despite privesc_confirmed turn: %s", rec)
	}

	// FP guard: a SECURE server that ignores the role field for a non-admin must NOT confirm.
	secRoles := map[string]string{"bob": "user"}
	sec := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sess, _ := r.Cookie("sess")
		if sess == nil {
			w.WriteHeader(401)
			return
		}
		switch r.URL.Path {
		case "/me":
			fmt.Fprintf(w, "user=%s role=%s", sess.Value, secRoles[sess.Value])
		case "/profile":
			// Secure: role is NOT settable from the body for a non-admin — ignored.
			fmt.Fprint(w, "updated")
		}
	}))
	defer sec.Close()
	cc2 := &Context{Target: sec.URL, ctx: context.Background()}
	cc2.req = NewRequester([]string{hostOf(sec.URL)}, 40, 0)
	tPrivescProbe(cc2, map[string]any{
		"session_cookie": "sess=bob",
		"verify_url":     sec.URL + "/me",
		"role_after":     "role=admin",
		"escalate":       map[string]any{"method": "POST", "url": sec.URL + "/profile", "body": map[string]any{"role": "admin"}},
	})
	if hasIndicator(cc2.History[len(cc2.History)-1], "privesc_confirmed") {
		t.Fatalf("secure server falsely confirmed privesc: %+v", cc2.History)
	}
}
