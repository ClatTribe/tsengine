// Package fieldevidence turns what happened AFTER a fix shipped into a corpus that calibrates how
// much evidence a later verification needs (ADR 0025, feed F1).
//
// THE SIGNAL. platform.FixVerification records what the ABSENCE check concluded (RescanSaidFixed)
// separately from what a live re-attack then proved (Disagreement). Its own comment states why:
// the two disagreeing is "a labelled example that absence-evidence was not enough, and it is the
// only way to answer 'what evidence is sufficient' from real data rather than from opinion".
//
// This package is that answer. For each rule CLASS it counts how often a clean re-scan was
// contradicted by a live exploit, and reports whether a clean re-scan is still sufficient evidence
// to make the terminal "fixed" claim for that class.
//
// WHAT IT MAY AND MAY NOT DO (ADR 0025). It can only ever DEMAND MORE evidence, never less. There is
// no path here that relaxes a check: a class with no data, thin data, or a clean record keeps exactly
// today's behaviour. Absence declares itself as "unknown" rather than as "trustworthy", and the
// caller's default for unknown is the status quo — so an empty corpus changes nothing at all.
//
// SCOPE TODAY: a tenant learning from its OWN verification history. That needs no consent and no
// anonymity threshold, because a tenant reading its own record is not a disclosure. The CROSS-tenant
// corpus is ADR 0025's next step and is what MinContributors exists for; the gate is built here so
// that promotion is a configuration change rather than a redesign.
package fieldevidence

import (
	"sort"
	"strings"
)

// Defaults. Each is a judgement, so each is stated rather than buried.
const (
	// DefaultMinObservations is how many clean re-scans a class needs before its record means
	// anything. One contradiction out of one re-scan is an anecdote, and acting on it would make the
	// product louder in exactly the way §10 forbids.
	DefaultMinObservations = 5
	// DefaultMinContributors is the k-anonymity gate for a CROSS-tenant corpus: a statistic computed
	// from one or two estates IS those estates' data. Irrelevant to a single-tenant corpus, which is
	// why the per-tenant constructor sets it to 1 explicitly rather than inheriting this.
	DefaultMinContributors = 3
	// DefaultMaxPerTenant bounds how many observations of ONE class a single tenant contributes, so
	// one large or one misconfigured estate cannot decide a shared statistic for everyone.
	DefaultMaxPerTenant = 5
	// DefaultContradictionThreshold is the rate at or above which a clean re-scan stops being
	// sufficient evidence. A re-scan that is wrong one time in ten while making a TERMINAL claim is
	// not a good enough basis for that claim.
	DefaultContradictionThreshold = 0.1
)

// Observation is one verified outcome: a re-scan said a finding was gone, and a live re-attack either
// agreed or contradicted it.
//
// Tenant is used ONLY for the contributor count and the per-tenant cap. It is deliberately not part
// of ClassEvidence, so nothing downstream can attribute a statistic to an estate.
type Observation struct {
	Tenant string
	// Class is the rule class — world-state (a public OSS rule id), never a customer's endpoint.
	Class string
	// Contradicted reports that a live re-attack proved the finding STILL exploitable after the
	// re-scan called it gone. False means the two kinds of evidence agreed.
	Contradicted bool
}

// ClassEvidence is what the corpus knows about one rule class. No tenant identifiers, by construction.
type ClassEvidence struct {
	Class string `json:"class"`
	// Contributors is the number of DISTINCT tenants behind this record.
	Contributors int `json:"contributors"`
	// CleanRescans is how many times a re-scan concluded the finding was gone.
	CleanRescans int `json:"clean_rescans"`
	// Contradicted is how many of those a live re-attack then disproved.
	Contradicted int `json:"contradicted"`
}

// ContradictionRate is the share of clean re-scans a live exploit disproved. Zero observations is 0 —
// callers must gate on Known rather than reading a zero rate as a clean record.
func (c ClassEvidence) ContradictionRate() float64 {
	if c.CleanRescans == 0 {
		return 0
	}
	return float64(c.Contradicted) / float64(c.CleanRescans)
}

// Options configures aggregation. A zero Options uses the documented defaults.
type Options struct {
	MinObservations        int
	MinContributors        int
	MaxPerTenant           int
	ContradictionThreshold float64
}

func (o Options) withDefaults() Options {
	if o.MinObservations <= 0 {
		o.MinObservations = DefaultMinObservations
	}
	if o.MinContributors <= 0 {
		o.MinContributors = DefaultMinContributors
	}
	if o.MaxPerTenant <= 0 {
		o.MaxPerTenant = DefaultMaxPerTenant
	}
	if o.ContradictionThreshold <= 0 {
		o.ContradictionThreshold = DefaultContradictionThreshold
	}
	return o
}

// Corpus is the aggregated record. Safe to share; never mutated after Aggregate returns.
type Corpus struct {
	Classes map[string]ClassEvidence `json:"classes"`
	Opts    Options                  `json:"-"`
}

// Aggregate folds observations into a corpus, applying the per-tenant cap during accumulation and the
// contributor/observation gates at publication.
//
// The per-tenant cap is applied to the CONTRADICTED and the clean counts together, by capping how
// many of a tenant's observations of a class are counted at all. Capping only one side would let a
// tenant with many clean re-scans dilute everyone else's contradictions, or the reverse.
func Aggregate(obs []Observation, opts Options) *Corpus {
	opts = opts.withDefaults()
	type acc struct {
		perTenant    map[string]int
		contributors map[string]bool
		clean        int
		contradicted int
	}
	byClass := map[string]*acc{}
	for _, o := range obs {
		class := strings.TrimSpace(o.Class)
		if class == "" {
			continue // never invent a class (§10)
		}
		a := byClass[class]
		if a == nil {
			a = &acc{perTenant: map[string]int{}, contributors: map[string]bool{}}
			byClass[class] = a
		}
		if a.perTenant[o.Tenant] >= opts.MaxPerTenant {
			continue // this tenant has already had its say about this class
		}
		a.perTenant[o.Tenant]++
		a.contributors[o.Tenant] = true
		a.clean++
		if o.Contradicted {
			a.contradicted++
		}
	}
	c := &Corpus{Classes: map[string]ClassEvidence{}, Opts: opts}
	for class, a := range byClass {
		c.Classes[class] = ClassEvidence{
			Class: class, Contributors: len(a.contributors),
			CleanRescans: a.clean, Contradicted: a.contradicted,
		}
	}
	return c
}

// RescanSufficient reports whether a clean re-scan alone may terminally confirm a fix for this class,
// and whether the corpus knows anything about it at all.
//
// known=false is the honest answer for no data, data below the observation floor, and data below the
// contributor floor. The caller must treat unknown as "unchanged", never as "trustworthy" and never
// as "suspect" — which is the difference between a corpus that calibrates and one that editorialises.
func (c *Corpus) RescanSufficient(class string) (sufficient, known bool) {
	if c == nil {
		return true, false
	}
	e, ok := c.Classes[strings.TrimSpace(class)]
	if !ok {
		return true, false
	}
	if e.CleanRescans < c.Opts.MinObservations || e.Contributors < c.Opts.MinContributors {
		return true, false
	}
	return e.ContradictionRate() < c.Opts.ContradictionThreshold, true
}

// Evidence returns the record for a class, for citing in the audit trail. ok=false when unknown.
func (c *Corpus) Evidence(class string) (ClassEvidence, bool) {
	if c == nil {
		return ClassEvidence{}, false
	}
	e, ok := c.Classes[strings.TrimSpace(class)]
	return e, ok
}

// Distrusted lists the classes whose clean re-scans are no longer sufficient, worst first. For the
// operator-facing view: this is the product stating where its own absence-evidence has failed.
func (c *Corpus) Distrusted() []ClassEvidence {
	if c == nil {
		return nil
	}
	var out []ClassEvidence
	for class, e := range c.Classes {
		if ok, known := c.RescanSufficient(class); known && !ok {
			out = append(out, e)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].ContradictionRate() != out[j].ContradictionRate() {
			return out[i].ContradictionRate() > out[j].ContradictionRate()
		}
		return out[i].Class < out[j].Class // stable: evidence is persisted and diffed
	})
	return out
}

// ClassOf extracts the rule class from a detect.Key ("rule_id|endpoint"). The class is world-state —
// a public OSS rule id — and the endpoint is the customer's, which is why the split lives in ONE
// place: every consumer must drop the endpoint half, and a second copy of this would eventually not.
func ClassOf(findingKey string) string {
	return strings.SplitN(findingKey, "|", 2)[0]
}
