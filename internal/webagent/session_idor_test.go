package webagent

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestSessionIDORProbe_EndToEnd: the stateful IDOR that a login POST trusts a client field to set the
// session, and the victim's data appears on a LATER GET (XBEN-043). Grounded by a TWO-ISOLATED-SESSION
// differential: session A logs in with the attacker's own id → GET target → no victim marker; session B
// logs in with the tampered victim id → GET target → victim marker present. The two logins differ ONLY
// in the tampered field, and the marker was never sent by the attacker — so it's FP-free (reuses
// tamperConfirmed). A server that ignores the client id (derives the user from real auth) must NOT fire.
func TestSessionIDORProbe_EndToEnd(t *testing.T) {
	// Vulnerable: /login trusts a client-supplied user_id to set the session; /dash renders that user.
	data := map[string]string{"10032": "your own boring profile", "10001": "SECRET victim flag{IDOR}"}
	newVuln := func() *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/login":
				_ = r.ParseForm()
				uid := r.PostFormValue("user_id") // IDOR: trusts the client-supplied id
				http.SetCookie(w, &http.Cookie{Name: "uid", Value: uid})
				fmt.Fprint(w, "logged in")
			case "/dash":
				c, _ := r.Cookie("uid")
				if c != nil {
					fmt.Fprint(w, data[c.Value])
					return
				}
				fmt.Fprint(w, "login first")
			}
		}))
	}
	vuln := newVuln()
	defer vuln.Close()
	cc := &Context{Target: vuln.URL, ctx: context.Background()}
	cc.req = NewRequester([]string{hostOf(vuln.URL)}, 40, 0)
	tSessionIDORProbe(cc, map[string]any{
		"login_url":         vuln.URL + "/login",
		"base_login_body":   "password=x&user_id=10032",
		"tamper_login_body": "password=x&user_id=10001",
		"target_url":        vuln.URL + "/dash",
		"marker":            "flag{IDOR}",
	})
	if len(cc.History) == 0 || !hasIndicator(cc.History[len(cc.History)-1], "tamper_confirmed") {
		t.Fatalf("session-state IDOR did not fire tamper_confirmed: %+v", cc.History)
	}
	tid := cc.History[len(cc.History)-1].ID
	if rec := tRecord(cc, map[string]any{"route": "/dash", "class": "idor", "evidence": []any{tid}}); strings.Contains(rec, "REJECTED") {
		t.Fatalf("idor rejected despite tamper_confirmed: %s", rec)
	}

	// FP guard: a server that IGNORES the client user_id (derives the rendered user from the session it
	// controls, not the client field) must NOT confirm — both sessions see their own data.
	sec := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/login":
			// secure: the server assigns the session's user regardless of the client user_id field
			http.SetCookie(w, &http.Cookie{Name: "uid", Value: "10032"})
			fmt.Fprint(w, "logged in")
		case "/dash":
			fmt.Fprint(w, data["10032"])
		}
	}))
	defer sec.Close()
	cc2 := &Context{Target: sec.URL, ctx: context.Background()}
	cc2.req = NewRequester([]string{hostOf(sec.URL)}, 40, 0)
	tSessionIDORProbe(cc2, map[string]any{
		"login_url": sec.URL + "/login", "base_login_body": "password=x&user_id=10032",
		"tamper_login_body": "password=x&user_id=10001", "target_url": sec.URL + "/dash", "marker": "flag{IDOR}",
	})
	if hasIndicator(cc2.History[len(cc2.History)-1], "tamper_confirmed") {
		t.Fatalf("server that ignores the client id falsely confirmed session IDOR: %+v", cc2.History)
	}
}
