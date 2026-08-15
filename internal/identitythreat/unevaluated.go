package identitythreat

import "sort"

// unevaluated.go answers a question the ingest could not: what did this batch NOT let us look for?
//
// Detect is correlation-based. Impossible travel needs two logins in different countries, spray
// needs a run of failures, MFA fatigue needs repeated challenges, and "MFA removed then access"
// needs both halves. Post a single successful login and NONE of the nine rules can fire — yet the
// response said `threats_detected: 0`, which a reader takes as "identity is clean".
//
// That matters most for the customer who wires up an IdP stream and posts events as they arrive.
// Detection runs over the BATCH it is given, so a one-event-per-request stream can never satisfy a
// correlation rule, and would report zero threats forever while looking like it was working.
//
// The sibling surface already does this: deviceposture.Report.ChecksNotRun exists so that silence
// about an unreported setting cannot read as a clean fleet. This is the same idea for identity.
//
// # Grounded, and deliberately not a second copy of the thresholds
//
// A check is reported unevaluable only when the batch lacks the EVENT MATERIAL it fundamentally
// needs — a rule about removed MFA factors cannot run without a removed-MFA event. It does not
// re-check Detect's numeric thresholds; duplicating those would create a second source of truth that
// drifts the first time one is tuned. So this understates: it names what was structurally
// impossible, not everything that happened to fall short.

// checkNeed describes what material a detection fundamentally requires.
type checkNeed struct {
	// name is the rule id as Detect emits it, so a reader can line the two up.
	name string
	// why is what a human needs to hear: what this looks for, and what it needs to see it.
	why string
	// satisfied reports whether the batch contains the material for this check to be possible.
	satisfied func(evidence) bool
}

// evidence is what the batch actually contained, counted once.
type evidence struct {
	logins, failures, challenges  int
	roleGrants, mfaRemovals       int
	usersWith2Logins              int
	usersWith2Failures            int
	distinctFailureIPs            int
	loginsWithCountry             int
	usersWithLoginAndFailure      int
	usersWithMFARemovalThenLogin  int
	usersWith2LoginsDistinctIPs   int
	usersWith2LoginsDistinctCntry int
}

// Unevaluated returns human-readable statements about the checks this batch could not exercise.
// Empty when every check had something to work with.
func Unevaluated(events []Event) []string {
	ev := summarize(events)
	var out []string
	for _, c := range checks() {
		if !c.satisfied(ev) {
			out = append(out, c.why)
		}
	}
	sort.Strings(out)
	return out
}

func checks() []checkNeed {
	return []checkNeed{
		{"privileged_grant", "Privileged-role grants: no role-grant events were in this batch, so an admin role handed out during this period would not have been seen.",
			func(e evidence) bool { return e.roleGrants > 0 }},
		{"mfa_removed", "MFA factor removals: no MFA-removal events were in this batch, so a security downgrade during this period would not have been seen.",
			func(e evidence) bool { return e.mfaRemovals > 0 }},
		{"mfa_removed_then_access", "MFA removed followed by access (the account-takeover sequence): needs both an MFA-removal and a later sign-in for the same person in the same batch.",
			func(e evidence) bool { return e.usersWithMFARemovalThenLogin > 0 }},
		{"impossible_travel", "Impossible travel: needs at least two sign-ins for the same person from different countries — this batch did not contain a pair with country information.",
			func(e evidence) bool { return e.usersWith2LoginsDistinctCntry > 0 }},
		{"concurrent_session", "Concurrent sessions from different IPs: needs at least two sign-ins for the same person from different addresses in this batch.",
			func(e evidence) bool { return e.usersWith2LoginsDistinctIPs > 0 }},
		{"password_spray", "Password spray against one account: needs repeated failed sign-ins for the same person in this batch.",
			func(e evidence) bool { return e.usersWith2Failures > 0 }},
		{"distributed_spray", "Distributed spray: needs failed sign-ins from more than one source address in this batch.",
			func(e evidence) bool { return e.distinctFailureIPs > 1 }},
		{"spray_success", "A spray that succeeded: needs failed sign-ins followed by a successful one for the same person in this batch.",
			func(e evidence) bool { return e.usersWithLoginAndFailure > 0 }},
		{"mfa_fatigue", "MFA fatigue (push bombing): needs repeated MFA challenges for the same person in this batch.",
			func(e evidence) bool { return e.challenges > 1 }},
	}
}

// summarize counts what the batch contains, once, so each check is a cheap predicate.
func summarize(events []Event) evidence {
	var e evidence
	logins := map[string][]Event{}
	failures := map[string]int{}
	failIPs := map[string]bool{}
	removals := map[string][]Event{}

	for _, x := range events {
		switch x.Type {
		case EventLogin:
			e.logins++
			logins[x.User] = append(logins[x.User], x)
			if x.Country != "" {
				e.loginsWithCountry++
			}
		case EventLoginFail:
			e.failures++
			failures[x.User]++
			if x.IP != "" {
				failIPs[x.IP] = true
			}
		case EventMFAChallenge:
			e.challenges++
		case EventRoleGrant:
			e.roleGrants++
		case EventMFARemoved:
			e.mfaRemovals++
			removals[x.User] = append(removals[x.User], x)
		}
	}
	e.distinctFailureIPs = len(failIPs)
	for u, ls := range logins {
		if len(ls) > 1 {
			e.usersWith2Logins++
			if distinct(ls, func(x Event) string { return x.IP }) > 1 {
				e.usersWith2LoginsDistinctIPs++
			}
			if distinct(ls, func(x Event) string { return x.Country }) > 1 {
				e.usersWith2LoginsDistinctCntry++
			}
		}
		if failures[u] > 0 {
			e.usersWithLoginAndFailure++
		}
		// The sequence rule needs a removal that PRECEDES a sign-in, not merely both being present.
		for _, rm := range removals[u] {
			for _, l := range ls {
				if l.Time.After(rm.Time) {
					e.usersWithMFARemovalThenLogin++
					break
				}
			}
			if e.usersWithMFARemovalThenLogin > 0 {
				break
			}
		}
	}
	for _, n := range failures {
		if n > 1 {
			e.usersWith2Failures++
		}
	}
	return e
}

// distinct counts unique non-empty keys. An absent field is not a distinct value — treating "" as
// one would let a batch with no country data look like it covered impossible travel.
func distinct[T any](in []T, key func(T) string) int {
	seen := map[string]bool{}
	for _, x := range in {
		if k := key(x); k != "" {
			seen[k] = true
		}
	}
	return len(seen)
}
