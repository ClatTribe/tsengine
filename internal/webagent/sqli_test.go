package webagent

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestSQLUnionEvaluated: a UNION-based SQLi grounds on an arithmetic SENTINEL the DB computes — the
// product of a multi-digit A*B placed in a UNION SELECT column appears in the response while the
// literal expression does not (the DB evaluated it). FP-free, mirroring ssti_eval: a mere reflection
// of the payload, or a product with no UNION context, must NOT fire.
func TestSQLUnionEvaluated(t *testing.T) {
	cases := []struct {
		name, payload, body string
		want                bool
	}{
		{"union arith computed", `1 UNION SELECT 1337*1337,2,3`, "row: 1787569 here", true},
		{"union arith computed lowercase", `zzz" union select 4242*4242,password,3#`, "User exists: 17994564", true},
		{"reflected literal NOT eval", `1 UNION SELECT 1337*1337`, "you sent 1 UNION SELECT 1337*1337", false},
		{"product but NO union context", `id=1337*1337`, "1787569", false},
		{"union but product absent", `1 UNION SELECT 1337*1337,2`, "No results", false},
		{"tiny product too collision-prone", `1 UNION SELECT 7*7`, "49 rows", false},
	}
	for _, c := range cases {
		if got := sqlUnionEvaluated(c.payload, c.body); got != c.want {
			t.Errorf("%s: sqlUnionEvaluated(%q,%q)=%v want %v", c.name, c.payload, c.body, got, c.want)
		}
	}
}

// TestSQLBooleanConfirmed: boolean-blind SQLi grounds on a differential — the TRUE condition
// reproduces the baseline result, the FALSE condition clearly does not, and the two diverge. A param
// that is merely reflected (echoed) or ignored produces no such pattern (no FP).
func TestSQLBooleanConfirmed(t *testing.T) {
	mk := func(status, n int) *Resp { return &Resp{Status: status, Body: strings.Repeat("x", n)} }
	cases := []struct {
		name           string
		base, tru, fls *Resp
		want           bool
	}{
		{"boolean blind", mk(200, 1000), mk(200, 1000), mk(200, 40), true},
		{"app ignores param (all same) NOT sqli", mk(200, 1000), mk(200, 1000), mk(200, 1000), false},
		{"reflection (true differs from base) NOT sqli", mk(200, 1000), mk(200, 1200), mk(200, 40), false},
		{"false only marginally different NOT confirmed", mk(200, 1000), mk(200, 1000), mk(200, 980), false},
		{"nil guard", nil, mk(200, 10), mk(200, 10), false},
	}
	for _, c := range cases {
		if got := sqlBooleanConfirmed(c.base, c.tru, c.fls); got != c.want {
			t.Errorf("%s: sqlBooleanConfirmed=%v want %v", c.name, got, c.want)
		}
	}
}

// TestSQLiBoolProbe_EndToEnd: a genuinely boolean-blind endpoint (a true condition returns the row,
// a false one returns nothing) fires sql_boolean and is recordable as class=sqli; an endpoint that
// just reflects the input does not.
func TestSQLiBoolProbe_EndToEnd(t *testing.T) {
	// Vulnerable: /item?q=<injected>; a TRUE boolean returns the secret row, FALSE returns empty.
	vuln := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		// crude simulation: the "SQL" returns the row unless a false-condition tail ('1'='2) is present.
		if strings.Contains(q, "'1'='2") || strings.Contains(q, "1=2") {
			fmt.Fprint(w, "no results")
			return
		}
		fmt.Fprint(w, "ITEM #1: the quarterly financials report body ................................")
	}))
	defer vuln.Close()

	cc := &Context{Target: vuln.URL, ctx: context.Background()}
	cc.req = NewRequester([]string{hostOf(vuln.URL)}, 40, 0)
	tSqliBoolProbe(cc, map[string]any{
		"method":    "GET",
		"base_url":  vuln.URL + "/item?q=1",
		"true_url":  vuln.URL + "/item?q=1'%20AND%20'1'='1",
		"false_url": vuln.URL + "/item?q=1'%20AND%20'1'='2",
	})
	if len(cc.History) == 0 || !hasIndicator(cc.History[len(cc.History)-1], "sql_boolean") {
		t.Fatalf("boolean-blind SQLi did not fire sql_boolean: %+v", cc.History)
	}
	tid := cc.History[len(cc.History)-1].ID
	rec := tRecord(cc, map[string]any{
		"route": "/item", "class": "sqli", "evidence": []any{tid},
		"severity": "high", "rationale": "boolean-blind SQL injection on q",
	})
	if strings.Contains(rec, "REJECTED") {
		t.Fatalf("sqli finding rejected despite sql_boolean turn: %s", rec)
	}

	// FP guard: an endpoint that just reflects the input must NOT confirm.
	refl := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "you searched for: %s", r.URL.Query().Get("q"))
	}))
	defer refl.Close()
	cc2 := &Context{Target: refl.URL, ctx: context.Background()}
	cc2.req = NewRequester([]string{hostOf(refl.URL)}, 40, 0)
	tSqliBoolProbe(cc2, map[string]any{
		"method": "GET", "base_url": refl.URL + "/item?q=1",
		"true_url": refl.URL + "/item?q=1'%20AND%20'1'='1", "false_url": refl.URL + "/item?q=1'%20AND%20'1'='2",
	})
	if hasIndicator(cc2.History[len(cc2.History)-1], "sql_boolean") {
		t.Fatalf("reflecting endpoint falsely confirmed boolean SQLi: %+v", cc2.History)
	}
}

// TestRecordFinding_SQLi_AnyOf: a sqli finding must be recordable when grounded by ANY of its valid
// indicators — sql_error (classic), sql_union (UNION sentinel), sql_boolean (differential), or
// slow_response (time-based). Before the any-of refactor only sql_error was accepted, so a UNION or
// boolean-blind capture (XBEN-095) could exploit but never RECORD the finding.
func TestRecordFinding_SQLi_AnyOf(t *testing.T) {
	for _, ind := range []string{"sql_error", "sql_union", "sql_boolean", "slow_response"} {
		cc := &Context{}
		cc.turnN = 1
		cc.History = []Turn{{ID: "t-001", Indicators: []string{ind}}}
		out := tRecord(cc, map[string]any{
			"route": "/x", "class": "sqli", "evidence": []any{"t-001"}, "severity": "high", "rationale": "sqli",
		})
		if strings.Contains(out, "REJECTED") {
			t.Errorf("sqli grounded by %q was rejected: %s", ind, out)
		}
	}
	// Negative: an unrelated indicator must still be rejected.
	cc := &Context{}
	cc.turnN = 1
	cc.History = []Turn{{ID: "t-001", Indicators: []string{"reflected_input"}}}
	out := tRecord(cc, map[string]any{"route": "/x", "class": "sqli", "evidence": []any{"t-001"}})
	if !strings.Contains(out, "REJECTED") {
		t.Errorf("sqli grounded only by reflected_input should be REJECTED: %s", out)
	}
}

// contains reports whether s is in xs (test helper for the any-of requiredIndicator).
func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}
