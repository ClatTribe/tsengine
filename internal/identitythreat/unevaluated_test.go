package identitythreat

import (
	"strings"
	"testing"
	"time"
)

// Detection here is CORRELATION-based, so a batch can be structurally incapable of exercising a
// rule. Reporting "0 threats" from such a batch is the same false all-clear the device-posture
// ingest already refuses to give (deviceposture.Report.ChecksNotRun). These hold the equivalent.

func mkEv(u string, k EventType, mins int, ip, country string) Event {
	return Event{User: u, Type: k, IP: ip, Country: country,
		Time: time.Date(2026, 8, 15, 10, mins, 0, 0, time.UTC)}
}

// THE CASE FOUND BY RUNNING THE PRODUCT: one successful login returned threats_detected:0 with
// nothing said about the eight rules that could not possibly have fired.
func TestUnevaluated_SingleLoginCannotExerciseTheCorrelationRules(t *testing.T) {
	out := Unevaluated([]Event{mkEv("ada@acme.io", EventLogin, 0, "1.2.3.4", "US")})
	if len(out) == 0 {
		t.Fatal("a single login reported nothing unevaluable — but impossible travel, spray, MFA " +
			"fatigue and the rest cannot fire on one event, so \"0 threats\" reads as a clean bill")
	}
	// The ones a lone login structurally cannot reach.
	for _, want := range []string{"Impossible travel", "Password spray", "MFA fatigue", "Privileged-role grants"} {
		found := false
		for _, s := range out {
			if strings.Contains(s, want) {
				found = true
			}
		}
		if !found {
			t.Errorf("%q not reported as unevaluable: %v", want, out)
		}
	}
}

// A batch that CAN exercise a rule must not claim otherwise — the guard has to distinguish, not
// blanket-warn, or it becomes noise nobody reads.
func TestUnevaluated_MaterialPresentIsNotReported(t *testing.T) {
	out := Unevaluated([]Event{
		mkEv("ada@acme.io", EventLogin, 0, "1.2.3.4", "US"),
		mkEv("ada@acme.io", EventLogin, 5, "9.9.9.9", "FR"),
	})
	for _, s := range out {
		if strings.Contains(s, "Impossible travel") {
			t.Error("two sign-ins from different countries: impossible travel WAS evaluable, " +
				"but it was reported as not run")
		}
		if strings.Contains(s, "Concurrent sessions") {
			t.Error("two sign-ins from different IPs: concurrent sessions WAS evaluable")
		}
	}
}

// Two sign-ins with NO country data cannot answer impossible travel. An absent field is not a
// value; treating "" as a distinct country would manufacture coverage that never happened.
func TestUnevaluated_MissingCountryIsNotCoverage(t *testing.T) {
	out := Unevaluated([]Event{
		mkEv("ada@acme.io", EventLogin, 0, "1.2.3.4", ""),
		mkEv("ada@acme.io", EventLogin, 5, "9.9.9.9", ""),
	})
	found := false
	for _, s := range out {
		if strings.Contains(s, "Impossible travel") {
			found = true
		}
	}
	if !found {
		t.Error("two sign-ins with no country information were treated as covering impossible travel")
	}

	// THE CASE THAT ACTUALLY CATCHES IT: one sign-in HAS a country and the other does not. Comparing
	// two countries needs two countries; counting the blank as a second distinct value manufactures
	// a comparison that cannot be made. (The all-blank case above does not catch this — both blanks
	// collapse to one value either way, which is how the weaker version of this test passed a
	// mutation that removed the guard.)
	mixed := Unevaluated([]Event{
		mkEv("ada@acme.io", EventLogin, 0, "1.2.3.4", "US"),
		mkEv("ada@acme.io", EventLogin, 5, "9.9.9.9", ""),
	})
	found = false
	for _, s := range mixed {
		if strings.Contains(s, "Impossible travel") {
			found = true
		}
	}
	if !found {
		t.Error("one sign-in with a country and one without was treated as a country PAIR — " +
			"impossible travel needs two countries to compare")
	}
}

// The account-takeover sequence needs the removal to PRECEDE the sign-in, not merely co-occur.
func TestUnevaluated_SequenceNeedsTheRightOrder(t *testing.T) {
	// Removal AFTER the login — the sequence rule still cannot be exercised.
	out := Unevaluated([]Event{
		mkEv("ada@acme.io", EventLogin, 0, "1.2.3.4", "US"),
		mkEv("ada@acme.io", EventMFARemoved, 30, "", ""),
	})
	found := false
	for _, s := range out {
		if strings.Contains(s, "MFA removed followed by access") {
			found = true
		}
	}
	if !found {
		t.Error("a removal that came AFTER the sign-in was treated as the takeover sequence")
	}

	// Correct order — now it is evaluable.
	out2 := Unevaluated([]Event{
		mkEv("ada@acme.io", EventMFARemoved, 0, "", ""),
		mkEv("ada@acme.io", EventLogin, 30, "1.2.3.4", "US"),
	})
	for _, s := range out2 {
		if strings.Contains(s, "MFA removed followed by access") {
			t.Error("removal then sign-in IS the sequence, but it was reported unevaluable")
		}
	}
}

// A rich batch that exercises everything reports nothing — otherwise the field is permanent noise.
func TestUnevaluated_RichBatchReportsNothing(t *testing.T) {
	events := []Event{
		mkEv("ada@acme.io", EventMFARemoved, 0, "", ""),
		mkEv("ada@acme.io", EventLogin, 5, "1.2.3.4", "US"),
		mkEv("ada@acme.io", EventLogin, 9, "9.9.9.9", "FR"),
		mkEv("ada@acme.io", EventLoginFail, 1, "5.5.5.5", "US"),
		mkEv("ada@acme.io", EventLoginFail, 2, "6.6.6.6", "US"),
		mkEv("ada@acme.io", EventMFAChallenge, 3, "", ""),
		mkEv("ada@acme.io", EventMFAChallenge, 4, "", ""),
		{User: "ada@acme.io", Type: EventRoleGrant, Admin: true,
			Time: time.Date(2026, 8, 15, 10, 6, 0, 0, time.UTC)},
	}
	if out := Unevaluated(events); len(out) != 0 {
		t.Errorf("a batch containing material for every rule still reported %d unevaluable: %v", len(out), out)
	}
}

// An empty batch says everything is unevaluable — nothing was posted, so nothing was examined.
func TestUnevaluated_EmptyBatchIsEntirelyUnevaluable(t *testing.T) {
	if out := Unevaluated(nil); len(out) != len(checks()) {
		t.Errorf("empty batch reported %d of %d checks unevaluable", len(out), len(checks()))
	}
}
