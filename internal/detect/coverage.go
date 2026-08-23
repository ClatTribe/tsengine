package detect

import "strings"

// coverage.go answers one question for the two consumers that reason from ABSENCE: was this pass
// authoritative ABOUT THIS PRODUCER?
//
// THE GAP IT CLOSES (ADR 0024 C16 / Sprint 0 R2). Reconcile RESOLVES an incident whose issue is
// missing from the pass, and retest.Verify marks a remediation FIXED on the same evidence. Both
// treated the pass as authoritative about everything. It is not: RescanTenant re-derives exactly
// four things — asset scans, SaaS posture, OSINT and cloud drift. The cloud engineer, the code
// engineer, codesweep, the CI-identity assessors, TPRM, device posture, the warehouse ingest and the
// identity event stream are ONE-SHOT. Nothing re-runs them, so their findings are absent from every
// pass by construction, and absence was being read as proof:
//
//	incident status after 3 routine passes: resolved (absent=2)
//	fix verification:                       fixed — "1 of 1 confirmed fixed in re-scan"
//
// Nobody had fixed anything and nothing had re-checked the path. FixStatusFixed is TERMINAL.
//
// THIS IS AN EXISTING DECISION APPLIED PER-PRODUCER. The runner already refuses to reconcile a
// tenant with no scannable assets, because "reconciling it would falsely RESOLVE the incidents the
// ingest path opened ... those are event-driven and stay open until a human resolves them". That is
// the right rule expressed at the wrong granularity — per TENANT, so one scannable asset re-enables
// the false resolve for every ingest producer on it. The runner's own comment called that "the
// ingest-incident-survives-a-scan-pass case", a documented follow-on. This is that follow-on.
//
// WHY COVERAGE MUST BE DECLARED AND CANNOT BE DERIVED FROM THE FINDINGS. A producer that ran and
// found nothing produces nothing, which is byte-identical to a producer that never ran. Deriving the
// covered set from `current` would therefore collapse the one distinction §10 exists to preserve, in
// the exact place it matters most. The caller that RAN the pass is the only thing that knows, so it
// has to say.

// Coverage is the set of producers a pass is authoritative about.
//
// The zero value covers NOTHING, which is deliberate: a caller that forgets to populate it concludes
// no resolutions and no confirmed fixes, which is a visible under-claim rather than a silent
// over-claim. Callers that genuinely sweep everything say so with AllProducers().
type Coverage struct {
	producers map[string]bool
	all       bool
}

// AllProducers asserts the caller observed the whole estate this pass. It is the back-compatible
// behaviour and stays available because some callers really do mean it — a full engine sweep, and
// the tests that predate this file.
func AllProducers() Coverage { return Coverage{all: true} }

// CoverageOf builds a Coverage from producer names — tool names as they appear in a finding's
// RuleID prefix ("nuclei", "grype", "osint", "cloudagent"). Empty names are ignored.
func CoverageOf(producers ...string) Coverage {
	c := Coverage{producers: make(map[string]bool, len(producers))}
	for _, p := range producers {
		if p = normalizeProducer(p); p != "" {
			c.producers[p] = true
		}
	}
	return c
}

// With returns a Coverage extended by more producers. Cheap to accumulate across a pass.
func (c Coverage) With(producers ...string) Coverage {
	if c.all {
		return c
	}
	out := Coverage{producers: make(map[string]bool, len(c.producers)+len(producers))}
	for p := range c.producers {
		out.producers[p] = true
	}
	for _, p := range producers {
		if p = normalizeProducer(p); p != "" {
			out.producers[p] = true
		}
	}
	return out
}

// Covers reports whether this pass can speak to the ABSENCE of a finding with this rule id.
//
// A rule id with no producer prefix cannot be attributed, and is treated as NOT covered. That errs
// toward leaving an incident open, which is the recoverable direction: a human closes an incident
// that should have closed itself, where the other way round the product tells them a live
// vulnerability was fixed.
func (c Coverage) Covers(ruleID string) bool {
	if c.all {
		return true
	}
	p := ProducerOf(ruleID)
	return p != "" && c.producers[p]
}

// Empty reports whether this Coverage can speak to nothing at all.
func (c Coverage) Empty() bool { return !c.all && len(c.producers) == 0 }

// ProducerOf extracts the producing tool from a rule id — the segment before the first "::", the
// convention every emitter in the tree follows ("nuclei::sqli-error-based",
// "cloudagent::attack-path::07e7", "osint::leaked-secret").
//
// It also accepts a full detect.Key ("<rule_id>|<endpoint>"), because retest reasons in keys rather
// than findings; the endpoint half can itself contain "::" (an ARN does not, but a URL with a port
// or an IPv6 host might), so the rule half is taken first.
func ProducerOf(ruleIDOrKey string) string {
	s := ruleIDOrKey
	if i := strings.Index(s, "|"); i >= 0 {
		s = s[:i]
	}
	i := strings.Index(s, "::")
	if i <= 0 {
		return ""
	}
	return normalizeProducer(s[:i])
}

func normalizeProducer(p string) string { return strings.ToLower(strings.TrimSpace(p)) }
