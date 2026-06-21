package identitythreat

import (
	"testing"
	"time"
)

var t0 = time.Date(2026, 6, 22, 9, 0, 0, 0, time.UTC)

func at(min int) time.Time { return t0.Add(time.Duration(min) * time.Minute) }

func rulesFor(threats []Threat) map[string]bool {
	m := map[string]bool{}
	for _, t := range threats {
		m[t.Rule] = true
	}
	return m
}

func TestImpossibleTravel(t *testing.T) {
	// Two logins, US then DE, 20 min apart → impossible travel.
	evs := []Event{
		{ID: "1", User: "ana", Type: EventLogin, Time: at(0), Country: "US"},
		{ID: "2", User: "ana", Type: EventLogin, Time: at(20), Country: "DE"},
	}
	if !rulesFor(Detect(evs, Config{}))["impossible_travel"] {
		t.Error("US→DE in 20 min must flag impossible travel")
	}

	// Same country → never fires.
	same := []Event{
		{User: "ana", Type: EventLogin, Time: at(0), Country: "US"},
		{User: "ana", Type: EventLogin, Time: at(20), Country: "US"},
	}
	if rulesFor(Detect(same, Config{}))["impossible_travel"] {
		t.Error("same-country logins must not fire (FP guard)")
	}

	// Different countries but far apart in time (> window) → legitimate travel, no fire.
	far := []Event{
		{User: "ana", Type: EventLogin, Time: at(0), Country: "US"},
		{User: "ana", Type: EventLogin, Time: at(600), Country: "DE"}, // 10h later
	}
	if rulesFor(Detect(far, Config{}))["impossible_travel"] {
		t.Error("a 10h gap is plausible travel — must not fire")
	}

	// Unknown geo (empty country) → never guess.
	unknown := []Event{
		{User: "ana", Type: EventLogin, Time: at(0), Country: ""},
		{User: "ana", Type: EventLogin, Time: at(10), Country: "DE"},
	}
	if rulesFor(Detect(unknown, Config{}))["impossible_travel"] {
		t.Error("an unknown-geo event must not produce an impossible-travel finding")
	}
}

func TestPrivilegedGrantAndMFARemoval(t *testing.T) {
	evs := []Event{
		{ID: "g", User: "bob", Type: EventRoleGrant, Time: at(0), Admin: true, Detail: "Super Admin"},
		{ID: "m", User: "bob", Type: EventMFARemoved, Time: at(5)},
		{ID: "g2", User: "cara", Type: EventRoleGrant, Time: at(0), Admin: false, Detail: "Viewer"}, // not privileged
	}
	r := rulesFor(Detect(evs, Config{}))
	if !r["privileged_grant"] || !r["mfa_removed"] {
		t.Errorf("a new admin grant + an MFA removal must both fire, got %v", r)
	}
	// A non-admin grant must not fire privileged_grant.
	for _, th := range Detect(evs, Config{}) {
		if th.Rule == "privileged_grant" && th.User == "cara" {
			t.Error("a non-privileged (Viewer) grant must not fire")
		}
	}
}

func TestPasswordSpray(t *testing.T) {
	var evs []Event
	for i := 0; i < 6; i++ { // 6 failed logins within 5 min
		evs = append(evs, Event{User: "dee", Type: EventLoginFail, Time: at(i)})
	}
	threats := Detect(evs, Config{})
	if !rulesFor(threats)["password_spray"] {
		t.Error("6 failed logins in 6 min should trip a spray alert (threshold 5/10m)")
	}

	// Below threshold → no fire.
	few := []Event{
		{User: "dee", Type: EventLoginFail, Time: at(0)},
		{User: "dee", Type: EventLoginFail, Time: at(1)},
	}
	if rulesFor(Detect(few, Config{}))["password_spray"] {
		t.Error("2 failed logins must not trip spray (FP guard)")
	}
}

func TestEvidenceGrounded(t *testing.T) {
	evs := []Event{
		{User: "ana", Type: EventLogin, Time: at(0), Country: "US", IP: "1.2.3.4"},
		{User: "ana", Type: EventLogin, Time: at(15), Country: "JP", IP: "9.8.7.6"},
	}
	for _, th := range Detect(evs, Config{}) {
		if len(th.Evidence) == 0 {
			t.Errorf("every threat must cite its backing events (§10), %s had none", th.Rule)
		}
	}
}
