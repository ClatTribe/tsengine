package webagent

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestCORSProbe_EndToEnd drives the full path — a server that reflects the request Origin with
// credentials must set cors_confirmed; a hardened server (fixed origin) must not. Proves the Resp
// header capture (ACAO/ACAC) + the handler wiring, not just the predicate.
func TestCORSProbe_EndToEnd(t *testing.T) {
	// vulnerable: reflects whatever Origin it's given + allows credentials
	vuln := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if o := r.Header.Get("Origin"); o != "" {
			w.Header().Set("Access-Control-Allow-Origin", o)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}
		_, _ = w.Write([]byte("ok"))
	}))
	defer vuln.Close()
	cc := &Context{ctx: context.Background()}
	cc.req = NewRequester([]string{hostOf(vuln.URL)}, 5, 0)
	out := tCORSProbe(cc, map[string]any{"url": vuln.URL})
	if !strings.Contains(out, "cors_confirmed —") {
		t.Fatalf("reflected-origin+credentials server must confirm CORS: %s", out)
	}
	if !hasIndicator(cc.History[len(cc.History)-1], "cors_confirmed") {
		t.Error("the recorded turn must carry the cors_confirmed indicator")
	}

	// hardened: pins one fixed trusted origin → must NOT confirm for our arbitrary origin
	safe := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "https://trusted.example.com")
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		_, _ = w.Write([]byte("ok"))
	}))
	defer safe.Close()
	cc2 := &Context{ctx: context.Background()}
	cc2.req = NewRequester([]string{hostOf(safe.URL)}, 5, 0)
	out2 := tCORSProbe(cc2, map[string]any{"url": safe.URL})
	if strings.Contains(out2, "cors_confirmed —") {
		t.Errorf("a fixed-trusted-origin server must NOT confirm CORS: %s", out2)
	}
}

// TestCORSConfirmed_FPFree pins the exact grounding boundary: a reflected arbitrary origin (or "null")
// WITH credentials grounds; every non-exploitable CORS shape does NOT.
func TestCORSConfirmed_FPFree(t *testing.T) {
	const attacker = "https://tsengine-cors-canary.attacker.example"
	cases := []struct {
		name   string
		resp   *Resp
		origin string
		want   bool
	}{
		{"reflected arbitrary origin + credentials", &Resp{ACAO: attacker, ACAC: true}, attacker, true},
		{"null origin + credentials", &Resp{ACAO: "null", ACAC: true}, attacker, true},
		{"reflected origin but NO credentials", &Resp{ACAO: attacker, ACAC: false}, attacker, false},
		{"wildcard + credentials (browser-forbidden, not exploitable)", &Resp{ACAO: "*", ACAC: true}, attacker, false},
		{"static trusted origin + credentials (does not reflect ours)", &Resp{ACAO: "https://app.example.com", ACAC: true}, attacker, false},
		{"no CORS headers at all", &Resp{}, attacker, false},
		{"nil response", nil, attacker, false},
		{"reflected but case-different origin still matches", &Resp{ACAO: "HTTPS://TSENGINE-CORS-CANARY.ATTACKER.EXAMPLE", ACAC: true}, attacker, true},
	}
	for _, c := range cases {
		if got := corsConfirmed(c.resp, c.origin); got != c.want {
			t.Errorf("%s: corsConfirmed = %v, want %v", c.name, got, c.want)
		}
	}
}

// TestCORS_IsGroundedClass: cors is wired into requiredIndicator so record_finding(class=cors) is
// rejected unless a cited turn carries cors_confirmed (parity with the other differential classes).
func TestCORS_IsGroundedClass(t *testing.T) {
	for _, class := range []string{"cors", "cors_misconfiguration", "cross_origin_resource_sharing"} {
		ind, ok := requiredIndicator[class]
		if !ok {
			t.Errorf("class %q must be a grounded class (in requiredIndicator)", class)
			continue
		}
		if !contains(ind, "cors_confirmed") {
			t.Errorf("class %q must require cors_confirmed, got %v", class, ind)
		}
	}
}
