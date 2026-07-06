package webagent

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestNoSQLiConfirmed_Predicate: NoSQL injection is grounded by a differential — a benign control
// request yields no privileged content, a request that adds a MongoDB operator ($ne/$regex/…) makes a
// SERVER-ORIGINATED marker appear that the attacker never sent. The Mongo-operator leg is what makes it
// specifically NoSQL (a generic value flip does not ground).
func TestNoSQLiConfirmed_Predicate(t *testing.T) {
	mk := func(body string) *Resp { return &Resp{Status: 200, Body: body} }
	cases := []struct {
		name            string
		control, inject *Resp
		marker, sent    string
		payload         string
		want            bool
	}{
		{"auth bypass via $ne", mk("Invalid credentials"), mk("Welcome admin flag{x}"), "Welcome admin", `username=a&password=b`, `{"username":{"$ne":null},"password":{"$ne":null}}`, true},
		{"query-string $ne form", mk("no user"), mk("Dashboard: victim flag{y}"), "flag{y}", `user=a`, `/login?user[$ne]=`, true},
		{"$regex filter bypass", mk("no results"), mk("Secret record flag{z}"), "Secret record", `q=x`, `{"q":{"$regex":".*"}}`, true},
		{"no mongo operator -> NOT (generic flip, not nosqli)", mk("Invalid"), mk("Welcome admin flag{x}"), "Welcome admin", `admin=1`, `admin=true`, false},
		{"echo FP: marker is the sent value", mk("x"), mk("$ne bypass"), "$ne", `{"$ne":null}`, `{"$ne":null}`, false},
		{"marker present in control too -> NOT", mk("Welcome flag{q}"), mk("Welcome flag{q}"), "flag{q}", `x`, `{"$ne":null}`, false},
		{"marker absent in inject -> NOT", mk("Invalid"), mk("Still invalid"), "Welcome admin", `x`, `{"$ne":null}`, false},
		{"too-short marker -> NOT", mk("ab"), mk("abc"), "abc", `x`, `{"$ne":null}`, false},
		{"nil guard", nil, mk("Welcome admin"), "Welcome admin", `x`, `{"$ne":null}`, false},
	}
	for _, c := range cases {
		if got := nosqliConfirmed(c.control, c.inject, c.marker, c.sent, c.payload); got != c.want {
			t.Errorf("%s: nosqliConfirmed=%v want %v", c.name, got, c.want)
		}
	}
}

func TestHasMongoOperator(t *testing.T) {
	yes := []string{`{"$ne":null}`, `user[$ne]=`, `{"password":{"$gt":""}}`, `{"$regex":".*"}`, `{"$where":"1==1"}`}
	no := []string{`admin=true`, `{"is_admin":true}`, `username=$money`, `price$100`, `just text`}
	for _, s := range yes {
		if !hasMongoOperator(s) {
			t.Errorf("hasMongoOperator(%q)=false, want true", s)
		}
	}
	for _, s := range no {
		if hasMongoOperator(s) {
			t.Errorf("hasMongoOperator(%q)=true, want false", s)
		}
	}
}

// TestNoSQLiProbe_EndToEnd: a Mongo-style login that treats {"$ne":null} as an always-true filter
// (auth bypass) fires nosqli_confirmed and records as class=nosqli; a server that compares the field
// as a plain string does not.
func TestNoSQLiProbe_EndToEnd(t *testing.T) {
	// vulnerable: any body containing $ne "logs in" (models pymongo find({username:{$ne:null}}))
	vuln := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b := make([]byte, r.ContentLength)
		_, _ = r.Body.Read(b)
		if strings.Contains(string(b), "$ne") {
			fmt.Fprint(w, "Welcome admin — flag{NOSQLI}")
			return
		}
		fmt.Fprint(w, "Invalid credentials")
	}))
	defer vuln.Close()

	cc := &Context{Target: vuln.URL, ctx: context.Background()}
	cc.req = NewRequester([]string{hostOf(vuln.URL)}, 40, 0)
	tNoSQLiProbe(cc, map[string]any{
		"method":       "POST",
		"url":          vuln.URL + "/login",
		"control_body": `{"username":"admin","password":"wrong"}`,
		"inject_body":  `{"username":{"$ne":null},"password":{"$ne":null}}`,
		"marker":       "Welcome admin",
	})
	if len(cc.History) == 0 || !hasIndicator(cc.History[len(cc.History)-1], "nosqli_confirmed") {
		t.Fatalf("vulnerable NoSQL login did not fire nosqli_confirmed: %+v", cc.History)
	}
	tid := cc.History[len(cc.History)-1].ID
	rec := tRecord(cc, map[string]any{
		"route": "/login", "class": "nosqli", "evidence": []any{tid},
		"severity": "critical", "rationale": "operator injection bypasses auth",
	})
	if !strings.Contains(rec, "recorded") {
		t.Fatalf("nosqli finding rejected despite nosqli_confirmed turn: %s", rec)
	}

	// safe server: compares fields as plain strings, ignores the operator -> no differential
	safe := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "Invalid credentials")
	}))
	defer safe.Close()
	cc2 := &Context{Target: safe.URL, ctx: context.Background()}
	cc2.req = NewRequester([]string{hostOf(safe.URL)}, 40, 0)
	tNoSQLiProbe(cc2, map[string]any{
		"method": "POST", "url": safe.URL + "/login",
		"control_body": `{"username":"admin","password":"wrong"}`,
		"inject_body":  `{"username":{"$ne":null},"password":{"$ne":null}}`,
		"marker":       "Welcome admin",
	})
	if len(cc2.History) > 0 && hasIndicator(cc2.History[len(cc2.History)-1], "nosqli_confirmed") {
		t.Fatalf("safe server wrongly fired nosqli_confirmed: %+v", cc2.History)
	}
}
