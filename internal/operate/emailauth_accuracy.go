package operate

import "time"

// This file is the email-auth accuracy harness — a labeled corpus of domain configs + a scorer
// that MEASURES the finding precision/recall the checks claim (the #323 SPF/DMARC depth checks +
// the hardened-domain → zero-findings invariant). Same sensitivity↔specificity discipline as the
// per-asset benches (CLAUDE.md §14.1.1), for this host-side deterministic posture core.

// LabeledDomain is one domain config + the COMPLETE set of operate:: rule ids a correct
// assessment emits on it. A hardened domain has Expect empty (the FP-control invariant).
type LabeledDomain struct {
	Name   string
	Config DomainConfig
	Expect []string
}

// DomainScore is the email-auth confusion tally. TP = an expected rule fired; FN = expected but
// missed; FP = a rule fired that wasn't expected (incl. ANY finding on a hardened domain).
type DomainScore struct {
	TP, FP, FN int
	Cases      int
	Hardened   int // count of Expect-empty (FP-control) domains
}

// Recall = TP / (TP + FN).
func (s DomainScore) Recall() float64 {
	if s.TP+s.FN == 0 {
		return 1
	}
	return float64(s.TP) / float64(s.TP+s.FN)
}

// Precision = TP / (TP + FP).
func (s DomainScore) Precision() float64 {
	if s.TP+s.FP == 0 {
		return 1
	}
	return float64(s.TP) / float64(s.TP+s.FP)
}

// ScoreDomains runs checkEmailAuth over each labeled domain and tallies TP/FP/FN against the labels.
func ScoreDomains(cases []LabeledDomain) DomainScore {
	now := time.Date(2026, 6, 22, 0, 0, 0, 0, time.UTC)
	s := DomainScore{Cases: len(cases)}
	for _, c := range cases {
		if len(c.Expect) == 0 {
			s.Hardened++
		}
		expect := map[string]bool{}
		for _, r := range c.Expect {
			expect[r] = true
		}
		n := 0
		id := func() string { n++; return "e" }
		got := map[string]bool{}
		for _, f := range checkEmailAuth(Workspace{Domains: []DomainConfig{c.Config}}, now, id) {
			got[f.RuleID] = true
		}
		for r := range expect {
			if got[r] {
				s.TP++
			} else {
				s.FN++
			}
		}
		for r := range got {
			if !expect[r] {
				s.FP++
			}
		}
	}
	return s
}

// EmailAuthCorpus is the built-in labeled corpus: one must-find domain per check (incl. the
// depth checks from #323) + hardened FP-control domains that must emit nothing.
func EmailAuthCorpus() []LabeledDomain {
	return []LabeledDomain{
		// --- must-find ---
		{"no_dmarc", DomainConfig{Name: "a.com", DMARC: "", SPF: true, DKIM: true}, []string{"operate::dmarc-not-enforced"}},
		{"spf_dkim_missing", DomainConfig{Name: "b.com", DMARC: "reject", SPF: false, DKIM: true}, []string{"operate::spf-dkim-missing"}},
		{"permissive_spf", DomainConfig{Name: "c.com", DMARC: "reject", SPF: true, DKIM: true, SPFAll: "+"}, []string{"operate::spf-permissive-all"}},
		{"partial_dmarc", DomainConfig{Name: "d.com", DMARC: "reject", SPF: true, DKIM: true, SPFAll: "-", DMARCPct: 25}, []string{"operate::dmarc-partial-enforcement"}},
		{"subdomain_gap", DomainConfig{Name: "e.com", DMARC: "quarantine", SPF: true, DKIM: true, SPFAll: "-", DMARCSub: "none"}, []string{"operate::dmarc-subdomain-unprotected"}},

		// --- hardened FP-control (must emit nothing) ---
		{"hardened_reject", DomainConfig{Name: "ok1.com", DMARC: "reject", SPF: true, DKIM: true, SPFAll: "-", DMARCPct: 100}, nil},
		{"hardened_quarantine_softfail", DomainConfig{Name: "ok2.com", DMARC: "quarantine", SPF: true, DKIM: true, SPFAll: "~"}, nil},
		{"hardened_legacy_snapshot", DomainConfig{Name: "ok3.com", DMARC: "reject", SPF: true, DKIM: true}, nil}, // no depth fields → must not trip them
	}
}
