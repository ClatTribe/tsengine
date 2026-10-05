package autonomy

import (
	"strings"
	"testing"
	"time"

	"github.com/ClatTribe/tsengine/pkg/platform"
)

var t0 = time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)

const cls, rt = "nuclei::sqli", "waf_rule"

func applied(id string, at time.Time, status string, classes ...string) platform.Action {
	var keys []string
	for _, c := range classes {
		keys = append(keys, c+"|https://x/"+id)
	}
	return platform.Action{ID: id, TenantID: "t1", Tier: platform.GateTier, Status: platform.ActApplied, DecidedAt: at,
		FindingKeys: keys, Payload: map[string]any{"remediation_type": rt},
		Verification: &platform.FixVerification{Status: status}}
}

func closes(n int, start time.Time) []platform.Action {
	var out []platform.Action
	for i := 0; i < n; i++ {
		out = append(out, applied("a"+string(rune('a'+i)), start.Add(time.Duration(i)*time.Hour), platform.FixStatusFixed, cls))
	}
	return out
}

func proposed(classes ...string) platform.Action {
	a := applied("new", t0.Add(30*24*time.Hour), "", classes...)
	a.Status, a.Verification = platform.ActProposed, nil
	return a
}

func grant() []platform.AutonomyGrant {
	return []platform.AutonomyGrant{{Class: cls, RemediationType: rt, GrantedBy: "owner@acme.com", GrantedAt: t0.Add(10 * 24 * time.Hour), BasisClosed: 5}}
}

// Offered only on a clean record of MinClosed closures — four is not five, and one failure or one
// unconfirmed re-test disqualifies however many closures sit beside it.
func TestOffer_OnlyOnACleanRecord(t *testing.T) {
	if r := Evaluate("t1", closes(4, t0), nil, Options{}); len(r.Offers) != 0 {
		t.Fatalf("four closures earned an offer: %+v", r.Offers)
	}
	five := closes(5, t0)
	if r := Evaluate("t1", five, nil, Options{}); len(r.Offers) != 1 || r.Offers[0].Closed != 5 {
		t.Fatalf("five clean closures must earn an offer: %+v", r.Offers)
	}
	for _, bad := range []string{platform.FixStatusStillPresent, platform.FixStatusRescanUnconfirmed} {
		acts := append(closes(9, t0), applied("bad", t0, bad, cls))
		if r := Evaluate("t1", acts, nil, Options{}); len(r.Offers) != 0 {
			t.Errorf("a %s application still earned an offer: %+v", bad, r.Offers)
		}
		if _, ok, why := Qualifies("t1", acts, cls, rt, Options{}); ok || why == "" {
			t.Errorf("Qualifies accepted a record with a %s application", bad)
		}
	}
	// A granted pair is not offered again.
	if r := Evaluate("t1", five, grant(), Options{}); len(r.Offers) != 0 || len(r.Grants) != 1 || !r.Grants[0].Active {
		t.Fatalf("granted: %+v", r)
	}
}

func TestAuthorize_OnlyTier2AndOnlyWhenEveryClassIsGranted(t *testing.T) {
	acts := closes(5, t0)
	who, ok := Authorize("t1", proposed(cls), acts, grant(), Options{})
	if !ok || !strings.Contains(who, "owner@acme.com") || !strings.Contains(who, rt) {
		t.Fatalf("a granted tier-2 action was not authorized, or the approver does not name the grant: %q", who)
	}
	t3 := proposed(cls)
	t3.Tier = platform.TierIrreversible
	if _, ok := Authorize("t1", t3, acts, grant(), Options{}); ok {
		t.Error("a T3 action was authorized — those need a named human signature, whatever the record")
	}
	if _, ok := Authorize("t1", proposed(cls, "semgrep::xss"), acts, grant(), Options{}); ok {
		t.Error("an action touching an ungranted class was authorized")
	}
	untyped := proposed(cls)
	untyped.Payload = nil
	if _, ok := Authorize("t1", untyped, acts, grant(), Options{}); ok {
		t.Error("an action with no remediation type was authorized")
	}
	if _, ok := Authorize("t1", proposed(cls), acts, nil, Options{}); ok {
		t.Error("authorized with no grant")
	}
}

// ONE FAILURE ENDS IT, read from the append-only history: a later clean re-test does not restore it.
func TestGrant_VoidedByTheFirstFailureUnderIt(t *testing.T) {
	acts := closes(5, t0)
	after := applied("under", t0.Add(20*24*time.Hour), platform.FixStatusFixed, cls)
	after.VerificationHistory = []platform.FixVerification{{Status: platform.FixStatusStillPresent}, {Status: platform.FixStatusFixed}}
	acts = append(acts, after)
	r := Evaluate("t1", acts, grant(), Options{})
	if len(r.Grants) != 1 || r.Grants[0].Active || !strings.Contains(r.Grants[0].Reason, "under") {
		t.Fatalf("a failure under the grant did not void it (or the reason does not name the action): %+v", r.Grants)
	}
	if _, ok := Authorize("t1", proposed(cls), acts, grant(), Options{}); ok {
		t.Fatal("a voided grant still authorized an action")
	}
}

// A closure the grant rested on, later contradicted, takes the grant with it.
func TestGrant_VoidedWhenItsBasisNoLongerHolds(t *testing.T) {
	acts := closes(5, t0)
	acts[0].Verification = &platform.FixVerification{Status: platform.FixStatusStillPresent}
	r := Evaluate("t1", acts, grant(), Options{})
	if r.Grants[0].Active || !strings.Contains(r.Grants[0].Reason, "no longer holds") {
		t.Fatalf("%+v", r.Grants[0])
	}
}
