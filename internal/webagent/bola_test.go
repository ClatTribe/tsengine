package webagent

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestBolaConfirmed_Predicate: the deterministic BOLA/IDOR differential is false-positive-free by
// construction (the apiauthz.Evaluate model). It fires ONLY when a victim-PRIVATE marker is:
//   - readable by the victim's OWN session (2xx) — proves the object belongs to the victim (baseline)
//   - AND readable by a DISTINCT attacker session (2xx) — the cross-principal violation
//   - AND NOT present to an unauthenticated request — proves it's access-controlled, not public.
// Any missing leg = not grounded (never assumed). This is what makes a one-session "different data on
// another id" heuristic (FP-prone on public per-object endpoints) safe to replace.
func TestBolaConfirmed_Predicate(t *testing.T) {
	mk := func(status int, body string) *Resp { return &Resp{Status: status, Body: body} }
	const marker = "victim@corp.example" // a victim-private datum

	cases := []struct {
		name                    string
		victim, attacker, unauth *Resp
		marker                  string
		want                    bool
	}{
		{"confirmed BOLA", mk(200, "acct "+marker), mk(200, "acct "+marker), mk(401, "login required"), marker, true},
		{"public endpoint (unauth sees it) NOT bola", mk(200, marker), mk(200, marker), mk(200, "acct "+marker), marker, false},
		{"attacker denied (proper authz) NOT bola", mk(200, marker), mk(403, "forbidden"), mk(401, "login"), marker, false},
		{"attacker 200 but marker absent NOT bola", mk(200, marker), mk(200, "your own acct alice@corp.example"), mk(401, ""), marker, false},
		{"victim baseline not readable NOT bola", mk(404, "not found"), mk(200, marker), mk(401, ""), marker, false},
		{"no unauth control -> refuse to ground", mk(200, marker), mk(200, marker), nil, marker, false},
		{"empty marker ungrounded", mk(200, "data"), mk(200, "data"), mk(401, ""), "", false},
		{"too-short marker ungrounded", mk(200, "a1"), mk(200, "a1"), mk(401, ""), "a1", false},
	}
	for _, c := range cases {
		got := bolaConfirmed(c.victim, c.attacker, c.unauth, c.marker)
		if got != c.want {
			t.Errorf("%s: bolaConfirmed = %v, want %v", c.name, got, c.want)
		}
	}
}

// TestBolaProbe_EndToEnd: a genuinely-vulnerable object endpoint (any logged-in user can read any
// account id) must produce a `bola_confirmed` turn the agent can then record as class=idor; a properly
// authorized endpoint (only the owner reads their id) must NOT, and neither must a public one.
func TestBolaProbe_EndToEnd(t *testing.T) {
	// Vulnerable server: /account?id=N returns that account's private email to ANY valid session
	// (attacker sess reads victim's id 2 == BOLA); unauth -> 401.
	vuln := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sess, _ := r.Cookie("sess")
		if sess == nil || (sess.Value != "victim" && sess.Value != "attacker") {
			w.WriteHeader(401)
			fmt.Fprint(w, "login required")
			return
		}
		id := r.URL.Query().Get("id")
		emails := map[string]string{"1": "attacker@corp.example", "2": "victim@corp.example"}
		fmt.Fprintf(w, "<h1>Account %s</h1><p>email: %s</p>", id, emails[id])
	}))
	defer vuln.Close()

	cc := &Context{Target: vuln.URL, ctx: context.Background()}
	cc.req = NewRequester([]string{hostOf(vuln.URL)}, 40, 0)

	tBolaProbe(cc, map[string]any{
		"url":             vuln.URL + "/account?id=2", // the VICTIM's object
		"attacker_cookie": "sess=attacker",
		"victim_cookie":   "sess=victim",
		"marker":          "victim@corp.example", // the victim-private datum from the victim baseline
	})
	if len(cc.History) == 0 || !hasIndicator(cc.History[len(cc.History)-1], "bola_confirmed") {
		t.Fatalf("vulnerable IDOR did not fire bola_confirmed: %+v", cc.History)
	}
	// The finding must now be recordable as idor, grounded by that turn.
	tid := cc.History[len(cc.History)-1].ID
	rec := tRecord(cc, map[string]any{
		"route": "/account?id=", "class": "idor", "evidence": []any{tid},
		"severity": "high", "rationale": "any authenticated user can read any account by id (BOLA)",
	})
	if strings.Contains(rec, "REJECTED") {
		t.Fatalf("idor finding rejected despite bola_confirmed turn: %s", rec)
	}

	// FP guard 1: a PROPERLY-AUTHORIZED server (only the owner's session reads their id) must NOT confirm.
	authz := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sess, _ := r.Cookie("sess")
		owner := map[string]string{"victim": "2", "attacker": "1"}
		id := r.URL.Query().Get("id")
		if sess == nil || owner[sess.Value] != id { // only your own id
			w.WriteHeader(403)
			fmt.Fprint(w, "forbidden")
			return
		}
		emails := map[string]string{"1": "attacker@corp.example", "2": "victim@corp.example"}
		fmt.Fprintf(w, "email: %s", emails[id])
	}))
	defer authz.Close()
	cc2 := &Context{Target: authz.URL, ctx: context.Background()}
	cc2.req = NewRequester([]string{hostOf(authz.URL)}, 40, 0)
	tBolaProbe(cc2, map[string]any{
		"url": authz.URL + "/account?id=2", "attacker_cookie": "sess=attacker",
		"victim_cookie": "sess=victim", "marker": "victim@corp.example",
	})
	if hasIndicator(cc2.History[len(cc2.History)-1], "bola_confirmed") {
		t.Fatalf("properly-authorized endpoint falsely confirmed BOLA: %+v", cc2.History)
	}
}
