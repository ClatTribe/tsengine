package identitythreat

import (
	"sort"
	"time"
)

// This file is the ITDR accuracy harness — a labeled corpus + a scorer that MEASURES the FP/FN
// accuracy the rules claim (not just unit-asserts a single case). It pairs must-find attack
// scenarios (recall) with benign FP-control scenarios (specificity), the same sensitivity↔
// specificity discipline as the per-asset benches (CLAUDE.md §14.1.1). LLM-free + deterministic.

// LabeledCase is one ground-truth scenario: an event stream + the COMPLETE set of rule names a
// correct detector fires on it (Expect). A benign FP-control case has Expect empty — a correct
// detector must produce nothing.
type LabeledCase struct {
	Name   string
	Events []Event
	Expect []string
}

// RuleScore is the per-rule tally.
type RuleScore struct{ TP, FN, FP int }

// Score is the accuracy result over a corpus. TP = an expected rule fired; FN = an expected rule
// missed; FP = a rule fired that the case did not expect (a spurious detection, incl. ANY rule on
// a benign case).
type Score struct {
	TP, FP, FN int
	Cases      int
	Benign     int // count of FP-control (Expect-empty) cases
	ByRule     map[string]RuleScore
}

// Recall = TP / (TP + FN) — of the threats that should fire, how many did. 1.0 when nothing missed.
func (s Score) Recall() float64 {
	if s.TP+s.FN == 0 {
		return 1
	}
	return float64(s.TP) / float64(s.TP+s.FN)
}

// Precision = TP / (TP + FP) — of the threats fired, how many were expected. 1.0 when no spurious.
func (s Score) Precision() float64 {
	if s.TP+s.FP == 0 {
		return 1
	}
	return float64(s.TP) / float64(s.TP+s.FP)
}

// ScoreCorpus runs Detect over each case and tallies TP/FP/FN against the labels.
func ScoreCorpus(cases []LabeledCase, cfg Config) Score {
	s := Score{Cases: len(cases), ByRule: map[string]RuleScore{}}
	for _, c := range cases {
		if len(c.Expect) == 0 {
			s.Benign++
		}
		expect := map[string]bool{}
		for _, r := range c.Expect {
			expect[r] = true
		}
		got := map[string]bool{}
		for _, t := range Detect(c.Events, cfg) {
			got[t.Rule] = true
		}
		for r := range expect {
			rs := s.ByRule[r]
			if got[r] {
				s.TP++
				rs.TP++
			} else {
				s.FN++
				rs.FN++
			}
			s.ByRule[r] = rs
		}
		for r := range got {
			if !expect[r] {
				s.FP++
				rs := s.ByRule[r]
				rs.FP++
				s.ByRule[r] = rs
			}
		}
	}
	return s
}

// Rules returns the rule names in the score, sorted (deterministic reporting).
func (s Score) Rules() []string {
	out := make([]string, 0, len(s.ByRule))
	for r := range s.ByRule {
		out = append(out, r)
	}
	sort.Strings(out)
	return out
}

// Corpus is the built-in labeled ITDR corpus: one must-find scenario per rule (Expect lists ALL
// rules that legitimately co-fire, e.g. spray_success implies password_spray, so a correct
// co-detection is not scored as a false positive) + benign FP-control scenarios that must produce
// zero threats. clock maps a minute offset to a timestamp (so the corpus is deterministic).
func Corpus(clock func(min int) time.Time) []LabeledCase {
	fail := func(user, ip string, m int) Event {
		return Event{User: user, Type: EventLoginFail, Time: clock(m), IP: ip}
	}
	login := func(user, country string, m int) Event {
		return Event{User: user, Type: EventLogin, Time: clock(m), Country: country}
	}
	mfaCh := func(user string, m int) Event { return Event{User: user, Type: EventMFAChallenge, Time: clock(m)} }

	var spray, spraySucc, fatigue, distrib []Event
	for i := 0; i < 5; i++ {
		spray = append(spray, fail("u1", "", i))
		spraySucc = append(spraySucc, fail("u2", "", i))
		fatigue = append(fatigue, mfaCh("u3", i))
	}
	spraySucc = append(spraySucc, login("u2", "US", 6))
	for i, u := range []string{"a", "b", "c", "d", "e", "f"} {
		distrib = append(distrib, fail(u, "203.0.113.7", i))
	}

	return []LabeledCase{
		// --- must-find (one per rule; Expect lists every rule that correctly fires) ---
		{"impossible_travel", []Event{login("ana", "US", 0), login("ana", "DE", 20)}, []string{"impossible_travel"}},
		{"password_spray", spray, []string{"password_spray"}},
		{"spray_success", spraySucc, []string{"password_spray", "spray_success"}},
		{"mfa_fatigue", fatigue, []string{"mfa_fatigue"}},
		{"distributed_spray", distrib, []string{"distributed_spray"}},
		{"privileged_grant", []Event{{User: "bob", Type: EventRoleGrant, Admin: true, Detail: "Admin", Time: clock(0)}}, []string{"privileged_grant"}},
		{"mfa_removed", []Event{{User: "cara", Type: EventMFARemoved, Time: clock(0)}}, []string{"mfa_removed"}},

		// --- benign FP-control (must produce zero threats) ---
		{"benign_same_country", []Event{login("dee", "US", 0), login("dee", "US", 30)}, nil},
		{"benign_few_fails", []Event{fail("dee", "", 0), fail("dee", "", 1)}, nil},
		{"benign_unknown_geo", []Event{login("dee", "", 0), login("dee", "DE", 5)}, nil},
		{"benign_few_mfa", []Event{mfaCh("dee", 0), mfaCh("dee", 1)}, nil},
		{"benign_spread_mfa", []Event{mfaCh("dee", 0), mfaCh("dee", 60), mfaCh("dee", 120), mfaCh("dee", 180), mfaCh("dee", 240)}, nil},
		{"benign_nonadmin_grant", []Event{{User: "dee", Type: EventRoleGrant, Admin: false, Detail: "Viewer", Time: clock(0)}}, nil},
		{"benign_two_users_one_ip", []Event{fail("a", "198.51.100.5", 0), fail("b", "198.51.100.5", 1)}, nil},
	}
}
