package webagent

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestTamperConfirmed_Predicate: broken access control via client-controlled-field tampering is
// grounded by a differential — a request that differs ONLY in a tampered field (a form field, a
// cookie/JWT claim) makes a SERVER-ORIGINATED privileged marker appear that the base request did not
// elicit AND that the attacker never sent. The "attacker didn't send it" leg kills the echo false
// positive (a marker that is merely the tampered value reflected back).
func TestTamperConfirmed_Predicate(t *testing.T) {
	mk := func(body string) *Resp { return &Resp{Status: 200, Body: body} }
	cases := []struct {
		name         string
		base, tamper *Resp
		marker, sent string
		want         bool
	}{
		{"param tamper privesc", mk("Incorrect username/password"), mk("Welcome Admin flag{x}"), "Welcome Admin", "username=x&password=x&isAdmin=true", true},
		{"jwt-forge idor (victim marker)", mk("Welcome, Test"), mk("Welcome, Flag flag{y}"), "flag{y}", "auth_token=eyJ...forged", true},
		{"echo FP: marker is the tampered value", mk("role=user"), mk("role=admin"), "admin", "role=admin", false},
		{"marker present in base too (not privileged) NOT", mk("Welcome flag{z}"), mk("Welcome flag{z}"), "flag{z}", "isAdmin=true", false},
		{"marker absent in tamper NOT", mk("Incorrect"), mk("Still incorrect"), "Welcome Admin", "isAdmin=true", false},
		{"too-short marker NOT", mk("ab"), mk("abc"), "abc", "x=1", false},
		{"nil guard", nil, mk("Welcome Admin"), "Welcome Admin", "isAdmin=true", false},
	}
	for _, c := range cases {
		if got := tamperConfirmed(c.base, c.tamper, c.marker, c.sent); got != c.want {
			t.Errorf("%s: tamperConfirmed=%v want %v", c.name, got, c.want)
		}
	}
}

// TestTamperProbe_EndToEnd_ParamTamper: a hidden-field mass-assignment privesc (server trusts a client
// isAdmin field) fires tamper_confirmed and records as class=privilege_escalation; a server that
// ignores the field does not.
func TestTamperProbe_EndToEnd_ParamTamper(t *testing.T) {
	vuln := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.PostFormValue("isAdmin") == "true" {
			fmt.Fprint(w, "Welcome Admin — flag{CTF}")
			return
		}
		fmt.Fprint(w, "Incorrect username/password")
	}))
	defer vuln.Close()

	cc := &Context{Target: vuln.URL, ctx: context.Background()}
	cc.req = NewRequester([]string{hostOf(vuln.URL)}, 40, 0)
	tTamperProbe(cc, map[string]any{
		"method":      "POST",
		"base_url":    vuln.URL + "/",
		"tamper_url":  vuln.URL + "/",
		"base_body":   "username=x&password=x&isAdmin=false",
		"tamper_body": "username=x&password=x&isAdmin=true",
		"marker":      "Welcome Admin",
	})
	if len(cc.History) == 0 || !hasIndicator(cc.History[len(cc.History)-1], "tamper_confirmed") {
		t.Fatalf("param-tamper privesc did not fire tamper_confirmed: %+v", cc.History)
	}
	tid := cc.History[len(cc.History)-1].ID
	rec := tRecord(cc, map[string]any{
		"route": "/", "class": "privilege_escalation", "evidence": []any{tid},
		"severity": "high", "rationale": "server trusts client isAdmin field",
	})
	if strings.Contains(rec, "REJECTED") {
		t.Fatalf("privilege_escalation rejected despite tamper_confirmed: %s", rec)
	}

	// FP guard: a server that ignores the field must NOT confirm.
	sec := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "Incorrect username/password")
	}))
	defer sec.Close()
	cc2 := &Context{Target: sec.URL, ctx: context.Background()}
	cc2.req = NewRequester([]string{hostOf(sec.URL)}, 40, 0)
	tTamperProbe(cc2, map[string]any{
		"method": "POST", "base_url": sec.URL + "/", "tamper_url": sec.URL + "/",
		"base_body": "isAdmin=false", "tamper_body": "isAdmin=true", "marker": "Welcome Admin",
	})
	if hasIndicator(cc2.History[len(cc2.History)-1], "tamper_confirmed") {
		t.Fatalf("field-ignoring server falsely confirmed tamper: %+v", cc2.History)
	}
}

// TestTamperProbe_EndToEnd_CookieForge: a cookie/token-forge IDOR (a client-controlled auth token whose
// claim selects the rendered user) fires tamper_confirmed via the base_cookie/tamper_cookie path.
func TestTamperProbe_EndToEnd_CookieForge(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, _ := r.Cookie("uid")
		if c != nil && c.Value == "10019" {
			fmt.Fprint(w, "Welcome, Flag flag{VICTIM}")
			return
		}
		fmt.Fprint(w, "Welcome, Test")
	}))
	defer srv.Close()
	cc := &Context{Target: srv.URL, ctx: context.Background()}
	cc.req = NewRequester([]string{hostOf(srv.URL)}, 40, 0)
	tTamperProbe(cc, map[string]any{
		"method": "GET", "base_url": srv.URL + "/dash", "tamper_url": srv.URL + "/dash",
		"base_cookie": "uid=10032", "tamper_cookie": "uid=10019", "marker": "flag{VICTIM}",
	})
	if !hasIndicator(cc.History[len(cc.History)-1], "tamper_confirmed") {
		t.Fatalf("cookie-forge IDOR did not fire tamper_confirmed: %+v", cc.History)
	}
	tid := cc.History[len(cc.History)-1].ID
	if rec := tRecord(cc, map[string]any{"route": "/dash", "class": "idor", "evidence": []any{tid}}); strings.Contains(rec, "REJECTED") {
		t.Fatalf("idor rejected despite tamper_confirmed: %s", rec)
	}
}
