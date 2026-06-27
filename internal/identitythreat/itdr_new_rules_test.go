package identitythreat

import (
	"testing"
	"time"
)

func ev2(user string, typ EventType, t time.Time, ip string) Event {
	return Event{User: user, Type: typ, Time: t, IP: ip, Country: "US"}
}

func ruleSet(threats []Threat) map[string]bool {
	m := map[string]bool{}
	for _, t := range threats {
		m[t.Rule] = true
	}
	return m
}

// Two successful logins from different IPs 2 minutes apart → session-token reuse.
func TestDetect_ConcurrentSession(t *testing.T) {
	base := time.Date(2026, 6, 27, 12, 0, 0, 0, time.UTC)
	evs := []Event{
		ev2("alice", EventLogin, base, "1.1.1.1"),
		ev2("alice", EventLogin, base.Add(2*time.Minute), "9.9.9.9"),
	}
	if !ruleSet(Detect(evs, Config{}))["concurrent_session"] {
		t.Error("two logins from different IPs within the window should flag concurrent_session")
	}
	// same IP → no concurrent-session flag (not reuse)
	same := []Event{ev2("bob", EventLogin, base, "1.1.1.1"), ev2("bob", EventLogin, base.Add(2*time.Minute), "1.1.1.1")}
	if ruleSet(Detect(same, Config{}))["concurrent_session"] {
		t.Error("same-IP logins must not flag concurrent_session")
	}
}

// MFA removed, then a login from a never-before-seen IP within the window → account-takeover sequence.
func TestDetect_MFARemovedThenAccess(t *testing.T) {
	base := time.Date(2026, 6, 27, 12, 0, 0, 0, time.UTC)
	evs := []Event{
		ev2("carol", EventLogin, base, "1.1.1.1"),                              // prior known IP
		ev2("carol", EventMFARemoved, base.Add(10*time.Minute), "1.1.1.1"),     // MFA disabled
		ev2("carol", EventLogin, base.Add(20*time.Minute), "9.9.9.9"),          // new IP login
	}
	r := ruleSet(Detect(evs, Config{}))
	if !r["mfa_removed_then_access"] {
		t.Error("MFA removed then new-IP login should flag mfa_removed_then_access")
	}
	// a login from the SAME (known) IP after MFA removal is not the ATO sequence
	known := []Event{
		ev2("dave", EventLogin, base, "1.1.1.1"),
		ev2("dave", EventMFARemoved, base.Add(10*time.Minute), "1.1.1.1"),
		ev2("dave", EventLogin, base.Add(20*time.Minute), "1.1.1.1"),
	}
	if ruleSet(Detect(known, Config{}))["mfa_removed_then_access"] {
		t.Error("a same-IP login after MFA removal must not flag the ATO sequence")
	}
}
