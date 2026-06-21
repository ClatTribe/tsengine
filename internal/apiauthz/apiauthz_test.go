package apiauthz

import (
	"context"
	"testing"

	"github.com/ClatTribe/tsengine/pkg/types"
)

func victim() Identity {
	return Identity{Name: "victim", Headers: map[string]string{"Authorization": "Bearer A"}}
}
func attacker() Identity {
	return Identity{Name: "attacker", Headers: map[string]string{"Authorization": "Bearer B"}}
}

func TestPlan_OnlyAuthzClasses(t *testing.T) {
	ops := []Operation{
		{Method: "GET", URL: "/invoices/42", Class: ClassBOLA},
		{Method: "DELETE", URL: "/admin/users/7", Class: ClassBFLA},
		{Method: "POST", URL: "/users", Class: "mass_assignment"}, // not an authz test here
	}
	plan := Plan(ops, victim(), attacker())
	if len(plan) != 2 {
		t.Fatalf("only BOLA+BFLA ops are planned, got %d", len(plan))
	}
}

func TestEvaluate_BOLA_Accuracy(t *testing.T) {
	test := AuthzTest{Op: Operation{Method: "GET", URL: "/invoices/42", Class: ClassBOLA, Marker: "victim@acme.com"}}
	baseline := Response{Status: 200, Body: `{"id":42,"owner":"victim@acme.com","total":900}`}

	// TRUE bypass: attacker got 200 AND the victim's data (marker present) → flagged.
	if v := Evaluate(test, baseline, Response{Status: 200, Body: `{"id":42,"owner":"victim@acme.com"}`}); !v.Bypassed {
		t.Error("a 2xx attacker response carrying the victim's data must be flagged as BOLA")
	}
	// Correctly DENIED (403) → not a finding (the secure outcome).
	if v := Evaluate(test, baseline, Response{Status: 403, Body: `{"error":"forbidden"}`}); v.Bypassed {
		t.Error("a 403 for the attacker is correctly denied — must NOT be a finding")
	}
	// 200 but WITHOUT the victim's data (attacker sees only their own / empty) → not a leak (FP guard).
	if v := Evaluate(test, baseline, Response{Status: 200, Body: `{"id":99,"owner":"attacker@evil.com"}`}); v.Bypassed {
		t.Error("a 2xx without the victim's data is not a proven leak — must NOT fire (low-FP)")
	}
	// 404 → object not found for the attacker (denied) → no finding.
	if v := Evaluate(test, baseline, Response{Status: 404, Body: ``}); v.Bypassed {
		t.Error("a 404 must not be a finding")
	}
}

func TestEvaluate_BOLA_BodyEqualityFallback(t *testing.T) {
	// No marker → fall back to body-equality (same object returned to the wrong principal).
	test := AuthzTest{Op: Operation{Method: "GET", URL: "/orders/5", Class: ClassBOLA}}
	body := `{"order":5,"items":["x","y"]}`
	if v := Evaluate(test, Response{200, body}, Response{200, body}); !v.Bypassed {
		t.Error("identical victim+attacker bodies (no marker) should flag a BOLA leak")
	}
	// A trivial/empty matching body must NOT count (guards an empty-200 false positive).
	if v := Evaluate(test, Response{200, "[]"}, Response{200, "[]"}); v.Bypassed {
		t.Error("a trivial matching body must not read as a leak")
	}
}

func TestEvaluate_BFLA(t *testing.T) {
	test := AuthzTest{Op: Operation{Method: "DELETE", URL: "/admin/users/7", Class: ClassBFLA}}
	// Low-priv attacker's privileged call succeeded → BFLA.
	if v := Evaluate(test, Response{200, ""}, Response{200, `{"deleted":true}`}); !v.Bypassed || v.Class != ClassBFLA {
		t.Error("an undenied privileged call must be flagged BFLA")
	}
	// Denied → correct, no finding.
	if v := Evaluate(test, Response{200, ""}, Response{403, ""}); v.Bypassed {
		t.Error("a denied privileged call must not be a finding")
	}
}

// fakeProber routes by the request's Authorization header so we can script victim vs attacker.
type fakeProber struct{ byAuth map[string]Response }

func (f fakeProber) Do(_ context.Context, r Request) (Response, error) {
	return f.byAuth[r.Headers["Authorization"]], nil
}

func TestRun_EmitsVerifiedFindings(t *testing.T) {
	plan := Plan([]Operation{{Method: "GET", URL: "/invoices/42", Class: ClassBOLA, Marker: "victim@acme.com"}}, victim(), attacker())
	prober := fakeProber{byAuth: map[string]Response{
		"Bearer A": {200, `{"owner":"victim@acme.com"}`}, // victim baseline
		"Bearer B": {200, `{"owner":"victim@acme.com"}`}, // attacker got the victim's data → BOLA
	}}
	out := Run(context.Background(), plan, prober, nil)
	if len(out) != 1 {
		t.Fatalf("expected 1 confirmed BOLA finding, got %d", len(out))
	}
	f := out[0]
	if f.RuleID != "apiauthz::bola" || f.VerificationStatus != types.VerificationVerified {
		t.Errorf("confirmed bypass should be a verified BOLA finding, got rule=%s status=%s", f.RuleID, f.VerificationStatus)
	}
	if len(f.CWE) == 0 || f.CWE[0] != "CWE-639" {
		t.Errorf("BOLA should map to CWE-639, got %v", f.CWE)
	}

	// nil prober → no live test, no findings (un-run leads; never falsely confident).
	if out := Run(context.Background(), plan, nil, nil); out != nil {
		t.Error("a nil prober must run nothing")
	}
}
