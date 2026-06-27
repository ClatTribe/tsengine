package operate

import (
	"testing"
	"time"
)

// A suspended account that still holds super-admin → incomplete-offboarding (high).
func TestAssess_IncompleteOffboarding(t *testing.T) {
	ws := Workspace{Org: "northwind", Users: []User{
		{Email: "ceo@nw.io", SuperAdmin: true, Suspended: true, MFA: true},        // suspended but still super-admin
		{Email: "ops@nw.io", Admin: true, Suspended: true, MFA: true},             // suspended but still admin
		{Email: "ok@nw.io", Admin: true, Suspended: true, MFA: true, LastLoginDays: 0}, // dup-ish: still flagged (admin)
	}}
	var got []string
	var sevSuper string
	for _, f := range Assess(ws, Options{Now: time.Now()}) {
		if f.RuleID == "operate::incomplete-offboarding" {
			got = append(got, f.Endpoint)
			if f.Endpoint == "ceo@nw.io" {
				sevSuper = string(f.Severity)
			}
			if f.Compliance == nil {
				t.Errorf("offboarding finding for %s missing compliance", f.Endpoint)
			}
		}
	}
	if len(got) != 3 {
		t.Fatalf("expected 3 incomplete-offboarding findings, got %d (%v)", len(got), got)
	}
	if sevSuper != "high" {
		t.Errorf("a suspended super-admin should be high severity, got %q", sevSuper)
	}
}

// A suspended NON-privileged account (cleanly offboarded) yields no offboarding finding.
func TestAssess_CleanOffboardingNoFinding(t *testing.T) {
	ws := Workspace{Org: "acme", Users: []User{
		{Email: "left@acme.io", Suspended: true, MFA: true},        // suspended, no roles → clean
		{Email: "active@acme.io", Admin: true, MFA: true},          // active admin → not an offboarding case
	}}
	for _, f := range Assess(ws, Options{Now: time.Now()}) {
		if f.RuleID == "operate::incomplete-offboarding" {
			t.Errorf("a cleanly-suspended non-privileged account must not flag incomplete-offboarding (got %s)", f.Endpoint)
		}
	}
}
