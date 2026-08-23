package fieldevidence

import (
	"sort"
	"strings"

	"github.com/ClatTribe/tsengine/pkg/platform"
)

// Feed F2 (ADR 0025): which remediation actually closed the finding.
//
// Both fix catalogs stamp a machine-readable remediation_type on the action they propose, and
// retest writes the outcome onto the same action. So "did this KIND of fix, for this KIND of
// finding, actually work?" is already answerable from stored data — it was simply never asked.
//
// It is worth more than a ranking: at the approval desk, "this remediation closed 9 of 10 times"
// and "this one was reopened 5 of 8 times" are different decisions for the human about to approve
// it, and today they read identically.

// RemediationEfficacy is what a tenant's history says about one (finding class, remediation type).
type RemediationEfficacy struct {
	Class string `json:"class"`
	Type  string `json:"remediation_type"`
	// Closed is how many times this remediation provably closed the finding.
	Closed int `json:"closed"`
	// NotClosed is how many times the finding was still present after it was applied.
	NotClosed int `json:"not_closed"`
	// Unproven counts applications whose re-scan said gone but was NOT accepted as confirmation
	// (F1). Reported, and deliberately EXCLUDED from the rate: counting "we do not know" as a
	// success is exactly the overclaim F1 exists to prevent, and folding it into the failures would
	// be the same error pointed the other way. It is surfaced so a reader can see the sample is
	// smaller than the number of applications.
	Unproven int `json:"unproven"`
}

// Decided is the number of applications that actually settled either way — the rate's denominator.
func (e RemediationEfficacy) Decided() int { return e.Closed + e.NotClosed }

// ClosureRate is the share of DECIDED applications that closed the finding. Zero decided is 0;
// callers must gate on the corpus's ok, never read a zero rate as "never works".
func (e RemediationEfficacy) ClosureRate() float64 {
	if e.Decided() == 0 {
		return 0
	}
	return float64(e.Closed) / float64(e.Decided())
}

// RemediationCorpus is the aggregated per-(class, type) record.
type RemediationCorpus struct {
	Entries map[string]RemediationEfficacy `json:"entries"`
	Opts    Options                        `json:"-"`
}

func remKey(class, rtype string) string { return class + "\x00" + rtype }

// RemediationsForTenant folds a tenant's own verified remediation history into the corpus.
//
// Single-tenant, like ForTenant and for the same reasons: no anonymity gate is needed to read your
// own record, and the per-tenant cap would truncate that record in arrival order. The evidence floor
// still applies, because one estate's anecdote is still an anecdote.
func RemediationsForTenant(tenant string, actions []platform.Action, opts Options) *RemediationCorpus {
	opts = opts.withDefaults()
	c := &RemediationCorpus{Entries: map[string]RemediationEfficacy{}, Opts: opts}
	for _, a := range actions {
		if a.Verification == nil || a.Status != platform.ActApplied {
			continue // never verified, or never applied — says nothing about whether the fix works
		}
		rtype := remediationTypeOf(a)
		if rtype == "" {
			continue // no machine-readable type → nothing to attribute the outcome to (§10)
		}
		seen := map[string]bool{}
		for _, k := range a.FindingKeys {
			class := strings.TrimSpace(ClassOf(k))
			if class == "" || seen[class] {
				continue // one outcome per DISTINCT class, as in FromActions
			}
			seen[class] = true
			key := remKey(class, rtype)
			e := c.Entries[key]
			e.Class, e.Type = class, rtype
			switch a.Verification.Status {
			case platform.FixStatusFixed:
				e.Closed++
			case platform.FixStatusStillPresent:
				e.NotClosed++
			case platform.FixStatusRescanUnconfirmed:
				e.Unproven++
			default:
				continue // an unrecognised status is not evidence in either direction
			}
			c.Entries[key] = e
		}
	}
	return c
}

// remediationTypeOf reads the machine-readable class of fix off the action, if it carries one.
func remediationTypeOf(a platform.Action) string {
	if a.Payload == nil {
		return ""
	}
	s, _ := a.Payload["remediation_type"].(string)
	return strings.TrimSpace(s)
}

// For returns the record for one (class, type), and whether there is enough of it to mean anything.
//
// ok=false for no history and for a history below the evidence floor. The caller must render nothing
// at all in that case: an efficacy of "0 of 0" beside a proposed fix reads as a fix that never works,
// which is the opposite of what the absence of data means.
func (c *RemediationCorpus) For(class, rtype string) (RemediationEfficacy, bool) {
	if c == nil {
		return RemediationEfficacy{}, false
	}
	e, ok := c.Entries[remKey(strings.TrimSpace(class), strings.TrimSpace(rtype))]
	if !ok || e.Decided() < c.Opts.MinObservations {
		return RemediationEfficacy{}, false
	}
	return e, true
}

// Weakest lists the remediations that most often failed to close, worst first — the ones whose
// runbooks are wrong and should be rewritten.
func (c *RemediationCorpus) Weakest() []RemediationEfficacy {
	if c == nil {
		return nil
	}
	var out []RemediationEfficacy
	for _, e := range c.Entries {
		if got, ok := c.For(e.Class, e.Type); ok && got.ClosureRate() < 1 {
			out = append(out, got)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].ClosureRate() != out[j].ClosureRate() {
			return out[i].ClosureRate() < out[j].ClosureRate()
		}
		if out[i].Class != out[j].Class {
			return out[i].Class < out[j].Class
		}
		return out[i].Type < out[j].Type
	})
	return out
}
