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

func TestSpraySuccess(t *testing.T) {
	// 5 fails then a success within the window → spray_success (takeover), critical.
	var evs []Event
	for i := 0; i < 5; i++ {
		evs = append(evs, Event{User: "eve", Type: EventLoginFail, Time: at(i)})
	}
	evs = append(evs, Event{User: "eve", Type: EventLogin, Time: at(6), Country: "US"})
	r := rulesFor(Detect(evs, Config{}))
	if !r["spray_success"] {
		t.Error("5 fails then a success in-window should fire spray_success")
	}
	for _, th := range Detect(evs, Config{}) {
		if th.Rule == "spray_success" && th.Severity != "critical" {
			t.Errorf("spray_success should be critical, got %s", th.Severity)
		}
	}

	// FP guard: a single fail then a success (normal fat-finger) must NOT fire.
	ok := []Event{
		{User: "eve", Type: EventLoginFail, Time: at(0)},
		{User: "eve", Type: EventLogin, Time: at(1), Country: "US"},
	}
	if rulesFor(Detect(ok, Config{}))["spray_success"] {
		t.Error("one fail then success must not fire spray_success (FP)")
	}

	// FP guard: 5 fails but the success is OUTSIDE the window must not fire.
	var late []Event
	for i := 0; i < 5; i++ {
		late = append(late, Event{User: "eve", Type: EventLoginFail, Time: at(i)})
	}
	late = append(late, Event{User: "eve", Type: EventLogin, Time: at(120), Country: "US"}) // 2h later
	if rulesFor(Detect(late, Config{}))["spray_success"] {
		t.Error("a success well outside the spray window must not fire spray_success (FP)")
	}
}

func TestMFAFatigue(t *testing.T) {
	// 5 MFA prompts within the window → mfa_fatigue.
	var evs []Event
	for i := 0; i < 5; i++ {
		evs = append(evs, Event{User: "fin", Type: EventMFAChallenge, Time: at(i)})
	}
	r := rulesFor(Detect(evs, Config{}))
	if !r["mfa_fatigue"] {
		t.Error("5 MFA prompts in-window should fire mfa_fatigue")
	}

	// Escalation: a login mid-burst → critical (the prompt was likely approved).
	withLogin := append([]Event{}, evs...)
	withLogin = append(withLogin, Event{User: "fin", Type: EventLogin, Time: at(3), Country: "US"})
	crit := false
	for _, th := range Detect(withLogin, Config{}) {
		if th.Rule == "mfa_fatigue" && th.Severity == "critical" {
			crit = true
		}
	}
	if !crit {
		t.Error("a login mid-burst should escalate mfa_fatigue to critical")
	}

	// FP guard: prompts spread beyond the window (normal periodic re-auth) must not fire.
	var spread []Event
	for i := 0; i < 5; i++ {
		spread = append(spread, Event{User: "fin", Type: EventMFAChallenge, Time: at(i * 60)}) // 1h apart
	}
	if rulesFor(Detect(spread, Config{}))["mfa_fatigue"] {
		t.Error("MFA prompts spread an hour apart must not fire mfa_fatigue (FP)")
	}
}

func TestDistributedSpray(t *testing.T) {
	// 6 distinct users each failing once from the same IP within the window → distributed spray.
	var evs []Event
	for i, u := range []string{"a", "b", "c", "d", "e", "f"} {
		evs = append(evs, Event{User: u, Type: EventLoginFail, Time: at(i), IP: "203.0.113.9"})
	}
	r := rulesFor(Detect(evs, Config{}))
	if !r["distributed_spray"] {
		t.Error("6 distinct users failing from one IP should fire distributed_spray")
	}
	// The per-user spray must NOT fire (no single user hit the per-user threshold).
	if r["password_spray"] {
		t.Error("no single user reached the per-user threshold; password_spray should not fire")
	}

	// FP guard 1: the same FEW users failing many times from one IP is per-user spray, not
	// distributed (only 2 distinct users < threshold 5).
	var fewUsers []Event
	for i := 0; i < 8; i++ {
		u := "a"
		if i%2 == 1 {
			u = "b"
		}
		fewUsers = append(fewUsers, Event{User: u, Type: EventLoginFail, Time: at(i), IP: "198.51.100.2"})
	}
	if rulesFor(Detect(fewUsers, Config{}))["distributed_spray"] {
		t.Error("only 2 distinct users must not fire distributed_spray (FP)")
	}

	// FP guard 2: failures with no source IP can't be attributed → no distributed finding.
	var noIP []Event
	for _, u := range []string{"a", "b", "c", "d", "e", "f"} {
		noIP = append(noIP, Event{User: u, Type: EventLoginFail, Time: at(0)})
	}
	if rulesFor(Detect(noIP, Config{}))["distributed_spray"] {
		t.Error("failures without a source IP must not fire distributed_spray (FP)")
	}
}
