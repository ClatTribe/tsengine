package ledger

import (
	"errors"
	"sort"
	"time"
)

// episode.go adds the one primitive the frontier-system ADR (0018) found outright
// missing: a security state bracketing an agent run, so a change can be ATTRIBUTED to
// the run that caused it.
//
// The tree already had the trajectory (Ledger.Steps), the commitments (Decisions), and
// three separate change detectors — detect.Reconcile diffs findings, clouddrift.Diff
// diffs cloud config, retest verifies a fix. What nothing did was snapshot a posture
// before an agent acted and again after, which is why an episode could not be scored:
// with no before and after, "the agent ran and things improved" is a story rather than
// a measurement, and a corpus of stories does not train anything.
//
// This package stays a LEAF — stdlib only. SecurityState therefore holds primitives and
// the CALLER censuses its own domain into it, exactly as Decision already works. That is
// deliberate: a state the ledger built itself would be a fifth change detector, and the
// ADR is explicit that the count stays at three.

// SecurityState is a point-in-time census of one scope's posture — the set of open
// issues and a few counted facts about them. It is deliberately not a copy of the
// findings: an episode record that embedded full findings would be a second store, and
// the keys are what a delta needs.
type SecurityState struct {
	At time.Time `json:"at"`
	// Scope names WHAT was censused — a target, an account, a repo. Two states with
	// different scopes are not comparable, and Diff refuses to pretend otherwise.
	Scope string `json:"scope"`
	// IssueKeys is the set of open issue keys, each the caller's stable identity for an
	// issue (crossdetect.DedupKey / detect.Key — never hand-rolled; a hand-built key has
	// silently matched nothing before).
	IssueKeys []string `json:"issue_keys,omitempty"`
	// BySeverity counts open issues per severity, so a delta can say a posture got worse
	// in kind and not only in number.
	BySeverity map[string]int `json:"by_severity,omitempty"`
	// Facts is the surface-specific census the caller supplies — privesc edges,
	// internet-reachable resources, admin principals. An open map because the interesting
	// facts differ per surface and a fixed struct here would need editing for each.
	Facts map[string]int `json:"facts,omitempty"`
}

// SecurityStateDelta is what changed between two states of the SAME scope.
type SecurityStateDelta struct {
	Scope string `json:"scope"`
	// Opened are keys present after and absent before; Closed the reverse.
	//
	// Closed means STOPPED APPEARING. It does not mean fixed, and the two must not be
	// read as one: a scan that failed, a tool that timed out, or a target that went
	// offline all close every key on this list. Whether a fix closed an issue is
	// retest.Verify's answer, in its own vocabulary, and it is a different claim
	// resting on different evidence.
	Opened []string `json:"opened,omitempty"`
	Closed []string `json:"closed,omitempty"`
	// Persisted counts keys present in both.
	Persisted     int            `json:"persisted"`
	SeverityDelta map[string]int `json:"severity_delta,omitempty"`
	FactDelta     map[string]int `json:"fact_delta,omitempty"`
}

// ErrScopeMismatch is returned by Diff when the two states censused different things.
var ErrScopeMismatch = errors.New("ledger: cannot diff security states of different scopes")

// Diff computes the change from before to after.
//
// Two refusals, and both are the difference between a measurement and a fabrication:
//
//   - DIFFERENT SCOPES → error. Diffing a repository census against a cloud census
//     would report every repository issue as Closed and every cloud issue as Opened,
//     and the number would look like spectacular progress. Nothing about the shapes
//     prevents it; only the check does.
//   - A MISSING BRACKET → error. No delta is computable from one snapshot, and the
//     tempting fallback — treat absent-before as empty — turns the first episode on
//     every target into a report that the agent opened every issue it merely found.
//     "We did not look" and "there was nothing" are different, which is the same rule
//     the coverage layer applies everywhere else.
func Diff(before, after *SecurityState) (*SecurityStateDelta, error) {
	if before == nil || after == nil {
		return nil, errors.New("ledger: a delta needs both brackets — one snapshot is not a change")
	}
	if before.Scope != after.Scope {
		return nil, ErrScopeMismatch
	}
	inBefore := map[string]bool{}
	for _, k := range before.IssueKeys {
		inBefore[k] = true
	}
	inAfter := map[string]bool{}
	for _, k := range after.IssueKeys {
		inAfter[k] = true
	}
	d := &SecurityStateDelta{Scope: after.Scope}
	for k := range inAfter {
		if inBefore[k] {
			d.Persisted++
		} else {
			d.Opened = append(d.Opened, k)
		}
	}
	for k := range inBefore {
		if !inAfter[k] {
			d.Closed = append(d.Closed, k)
		}
	}
	sort.Strings(d.Opened)
	sort.Strings(d.Closed)
	d.SeverityDelta = countDelta(before.BySeverity, after.BySeverity)
	d.FactDelta = countDelta(before.Facts, after.Facts)
	return d, nil
}

// countDelta subtracts before from after over the union of keys, dropping zeros so an
// unchanged count does not read as a reported change.
func countDelta(before, after map[string]int) map[string]int {
	if len(before) == 0 && len(after) == 0 {
		return nil
	}
	out := map[string]int{}
	for k, v := range after {
		if v-before[k] != 0 {
			out[k] = v - before[k]
		}
	}
	for k, v := range before {
		if _, seen := after[k]; !seen && v != 0 {
			out[k] = -v
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// Cost is what an episode spent. Cost per VERIFIED outcome is the metric the ADR makes
// first-class: the raw spend is not interesting, and neither is the raw finding count —
// dividing one by the other is what says whether a run was worth making.
type Cost struct {
	USD        float64 `json:"usd"`
	Tokens     int     `json:"tokens"`
	Iterations int     `json:"iterations"`
	// WallClock is separate from tokens because a sandbox-heavy episode can be cheap in
	// tokens and expensive in machine time, and for a BYOK tenant that second number is
	// the one WE pay.
	WallClock time.Duration `json:"wall_clock_ns,omitempty"`
}

// Training records whether this episode may be used to improve the system, captured at
// WRITE time. It is not inferrable later: consent given today does not reach backwards
// over data already collected, so an episode written without it is permanently
// non-trainable rather than pending.
type Training struct {
	Consented   bool      `json:"consented"`
	ConsentedBy string    `json:"consented_by,omitempty"`
	ConsentedAt time.Time `json:"consented_at,omitzero"`
	// Statement is the text the customer actually agreed to, kept verbatim so an
	// auditor reads what was consented to rather than our summary of it — the same
	// discipline pentest.RoE applies to active-exploitation consent.
	Statement string `json:"statement,omitempty"`
}

// Episode is one agent run, scored. It WRAPS a Ledger rather than replacing it: the
// ledger remains the signed trajectory and every existing consumer is untouched.
//
// The four status axes stay four fields. Document D proposed collapsing them into a
// single SUCCESS | FAILURE | FALSE_POSITIVE | INCONCLUSIVE | HUMAN_ESCALATION enum, and
// that flattening loses cases the tree exists to express — most sharply "the loop
// finished cleanly, the finding is verified real, and the fix did not close it", which
// is precisely what retest.ApplyReattack was written to catch. One enum cannot say it.
type Episode struct {
	Ledger *Ledger `json:"ledger"`

	// Before/After bracket the run. Either may be nil, and then Delta is nil too — a
	// half-bracketed episode is honestly unscored rather than optimistically zero.
	Before *SecurityState      `json:"before,omitempty"`
	After  *SecurityState      `json:"after,omitempty"`
	Delta  *SecurityStateDelta `json:"delta,omitempty"`

	// Fields that cannot be retrofitted, so they exist from day one.
	//
	// Difficulty is the caller's stratification label. A corpus with no difficulty
	// signal cannot tell a model that got harder problems from a model that got worse,
	// and the label cannot be recovered once the target has changed.
	Difficulty string `json:"difficulty,omitempty"`
	// AgentVersion identifies what produced this. Without it a benchmark movement
	// cannot be attributed to a change, which makes the whole corpus retrospective
	// rather than causal.
	AgentVersion string   `json:"agent_version,omitempty"`
	Model        string   `json:"model,omitempty"`
	Training     Training `json:"training"`
	Cost         Cost     `json:"cost"`

	// The four independent status axes — see the type comment. Each is the string form
	// of the vocabulary its own package owns; this package deliberately declares no
	// enum, so a new value there needs no change here.
	// Unscored says WHY there is no delta, when there is none. A nil delta with no
	// reason is indistinguishable from a run that changed nothing, and those are
	// opposite facts: one is "we could not measure", the other is "we measured, and
	// nothing moved".
	Unscored string `json:"unscored,omitempty"`

	StopReason   string `json:"stop_reason,omitempty"`   // l2.StopReason
	Verification string `json:"verification,omitempty"`  // types.VerificationState
	FixStatus    string `json:"fix_status,omitempty"`    // platform.FixStatus / retest.Status
	HumanVerdict string `json:"human_verdict,omitempty"` // tenanteval.Verdict
}

// NewEpisode brackets a ledger with its before-state and the day-one metadata.
// after is supplied later by Close.
func NewEpisode(l *Ledger, before *SecurityState) *Episode {
	return &Episode{Ledger: l, Before: before}
}

// Close records the after-state and computes the delta.
//
// A scope mismatch or a missing bracket leaves Delta nil and returns the error. The
// episode is still valid and still retained — a run whose posture change could not be
// measured is a real run that we cannot score, and dropping it would bias the corpus
// toward exactly the episodes that went smoothly.
func (e *Episode) Close(after *SecurityState) error {
	if e == nil {
		return errors.New("ledger: Close on a nil episode")
	}
	e.After = after
	d, err := Diff(e.Before, after)
	if err != nil {
		e.Delta = nil
		e.Unscored = err.Error()
		return err
	}
	e.Delta, e.Unscored = d, ""
	return nil
}

// Trainable reports whether this episode may be used to improve the system.
//
// Failed episodes ARE trainable and are retained first-class: an agent that only ever
// sees its successes learns that everything works. What gates training is consent, and
// nothing else.
func (e *Episode) Trainable() bool {
	return e != nil && e.Training.Consented
}

// ErrConsentNotRetroactive is returned by GrantConsent on an episode that already
// closed. See the method.
var ErrConsentNotRetroactive = errors.New("ledger: training consent cannot be granted after the episode is written")

// GrantConsent records consent, and REFUSES once the episode has an after-state.
//
// This looks like an unhelpful restriction and is the entire point. The failure it
// prevents is retroactive consent: a customer agrees today, and the runs already sitting
// in the corpus — collected while they had agreed to nothing — silently become training
// data. Marking them consented would be a lie told by a timestamp, and it is the kind
// nobody catches, because the record would look perfectly consistent afterwards.
func (e *Episode) GrantConsent(by, statement string, at time.Time) error {
	if e == nil {
		return errors.New("ledger: GrantConsent on a nil episode")
	}
	if e.After != nil {
		return ErrConsentNotRetroactive
	}
	e.Training = Training{Consented: true, ConsentedBy: by, ConsentedAt: at, Statement: statement}
	return nil
}

// CostPerVerified divides spend by the verified outcomes this episode produced, and
// reports whether the number means anything.
//
// ok=false when nothing was verified. That is not a zero and not an infinity: an episode
// that verified nothing has no cost-per-outcome, and averaging a sentinel into a fleet
// number would quietly make the cheapest agent the one that finds nothing.
func (e *Episode) CostPerVerified(verified int) (float64, bool) {
	if e == nil || verified <= 0 {
		return 0, false
	}
	return e.Cost.USD / float64(verified), true
}
