// Package auditreview is the layer between "the engine found things" and "a named human signs a
// certificate" — the step that actually costs an empanelled audit firm money.
//
// # What this is for
//
// A CERT-In-empanelled firm sells a per-application audit ending in a certificate. Their cost is not
// the scan; it is the qualified reviewer who must decide, finding by finding, what goes into a
// document they put their name on. This package is that decision, recorded.
//
// # The compression is ATTENTION, not automation
//
// It would be easy and wrong to auto-include everything above a confidence threshold. The reviewer
// is signing; the machine cannot take that decision, and a tool that quietly made it would be
// manufacturing exactly the false confidence §10 exists to prevent.
//
// What CAN be done is tell the reviewer where their judgement is actually load-bearing. A finding
// the agent EXPLOITED, with a captured proof, needs a glance. A pattern-match with no corroboration
// is one the reviewer is staking their name on with the scanner's word for it. `Load` states that
// split, so an hour of review goes to the four findings that need it rather than spread evenly over
// twelve. That is the whole product: the same decisions, made in the right order, with the evidence
// already assembled.
//
// # Rebuilt from CURRENT findings, never frozen
//
// Like internal/recertify, a review is recomputed on every read from the findings in scope now, with
// stored dispositions merged back on. A frozen snapshot would send a reviewer to sign off an
// application whose latest scan found something nobody has looked at — and the re-test step in every
// one of these tenders guarantees the finding set moves between draft and final report.
package auditreview

import (
	"errors"
	"sort"
	"strings"
	"time"

	"github.com/ClatTribe/tsengine/pkg/types"
)

// Verdict is what a reviewer decided about one finding's place in the signed report.
type Verdict string

const (
	// VerdictPending is the zero value — nobody has looked at this finding yet.
	VerdictPending Verdict = ""
	// VerdictInclude puts the finding in the report as the engine reported it.
	VerdictInclude Verdict = "include"
	// VerdictExclude keeps it OUT of the report. It never deletes it: the finding stays in the audit
	// trail with who excluded it and why, because if the application is later compromised through an
	// excluded finding, that record is the only thing between the auditor and negligence.
	VerdictExclude Verdict = "exclude"
	// VerdictReclassify keeps the finding but at the REVIEWER's severity.
	//
	// Named for either direction on purpose. "Downgrade" would presume one, and a reviewer who knows
	// the application is internet-facing and holds regulated data may legitimately raise a medium.
	// The direction is recorded (Lowered) because lowering is the risky one — it is what makes a
	// report look better, and what a later compromise exposes.
	VerdictReclassify Verdict = "reclassify"
)

func (v Verdict) Valid() bool {
	return v == VerdictInclude || v == VerdictExclude || v == VerdictReclassify
}

// NeedsReason reports whether this verdict may not be recorded bare. An inclusion speaks for itself —
// the engine's evidence is the reason. Removing a finding from a signed report, or changing the
// severity it carries, is the reviewer's own claim and has to say why.
func (v Verdict) NeedsReason() bool { return v == VerdictExclude || v == VerdictReclassify }

// Disposition is one reviewer's decision about one finding, by name and on a date.
type Disposition struct {
	TenantID string  `json:"tenant_id"`
	Target   string  `json:"target"` // the application under audit
	Key      string  `json:"key"`    // the finding key (crossdetect.DedupKey), stable across re-scans
	Verdict  Verdict `json:"verdict"`
	// Severity is the reviewer's severity, for a reclassification only.
	Severity string `json:"severity,omitempty"`
	// Lowered records that the reclassification REDUCED severity — the direction that makes a report
	// look better, surfaced so a reader can see it was a human judgement and not the scanner's.
	Lowered bool      `json:"lowered,omitempty"`
	Reason  string    `json:"reason,omitempty"`
	By      string    `json:"by"`
	At      time.Time `json:"at"`
}

// ID is the storage key: one decision per finding per application.
func (d Disposition) ID() string { return strings.ToLower(strings.TrimSpace(d.Target)) + "|" + d.Key }

// Item is one finding as the reviewer sees it: the engine's evidence, and the decision so far.
type Item struct {
	Key       string   `json:"key"`
	FindingID string   `json:"finding_id"`
	Title     string   `json:"title"`
	Severity  string   `json:"severity"` // as the engine reported it
	Endpoint  string   `json:"endpoint,omitempty"`
	RuleID    string   `json:"rule_id,omitempty"`
	CWE       []string `json:"cwe,omitempty"`
	OWASP     []string `json:"owasp,omitempty"`

	// The evidence the reviewer is being asked to stand behind. Rung is HOW it was established;
	// Proven means a predicate ran and held, which is the difference between a glance and an hour.
	Rung       string  `json:"rung,omitempty"`
	Confidence float64 `json:"confidence,omitempty"`
	// Proven means a predicate RAN and held — exploited, or confirmed by the provider's own
	// evaluator. It is taken from the rung rather than recomputed, so this package and the VAPT
	// report cannot disagree about what counts as proof.
	Proven bool `json:"proven"`

	// EffectiveSeverity is what the report will carry: the reviewer's, where they set one.
	EffectiveSeverity string  `json:"effective_severity"`
	Verdict           Verdict `json:"verdict"`
	Reason            string  `json:"reason,omitempty"`
	By                string  `json:"by,omitempty"`
	At                string  `json:"at,omitempty"`
	Lowered           bool    `json:"lowered,omitempty"`
}

// Load is where the reviewer's judgement is actually required — the package's reason to exist.
type Load struct {
	// Proven findings carry a predicate that RAN and held (exploited, or a provider confirmation).
	// The reviewer is checking the engine's work, not supplying the evidence.
	Proven int `json:"proven"`
	// Unproven rests on a scanner's pattern match. Signing these is the reviewer putting their name
	// where the engine could not prove it — the minutes that matter.
	Unproven int `json:"unproven"`
	// Detail says it in words, because two numbers side by side do not tell a reader which one is
	// the one to worry about.
	Detail string `json:"detail"`
}

// Progress is the honest state of a review.
type Progress struct {
	Total        int `json:"total"`
	Reviewed     int `json:"reviewed"`
	Pending      int `json:"pending"`
	Included     int `json:"included"`
	Excluded     int `json:"excluded"`
	Reclassified int `json:"reclassified"`
	// Complete is true only when EVERY finding has a decision. An empty review is NOT complete:
	// "0 of 0 reviewed" would issue a certificate for an application nobody looked at, which is the
	// one outcome this package exists to make impossible.
	Complete bool   `json:"complete"`
	Load     Load   `json:"load"`
	Detail   string `json:"detail"`
}

// Review is one application's audit, recomputed from current findings each read.
type Review struct {
	Target   string   `json:"target"`
	Standard string   `json:"standard,omitempty"`
	Items    []Item   `json:"items"`
	Progress Progress `json:"progress"`
}

// Build assembles the review for one application from the findings in scope and the decisions taken
// so far. `key` derives the stable finding key (crossdetect.DedupKey) — injected so this package does
// not depend on the correlation layer.
func Build(target, standard string, findings []types.Finding, key func(types.Finding) string,
	dispositions []Disposition) Review {

	byKey := map[string]Disposition{}
	for _, d := range dispositions {
		if strings.EqualFold(strings.TrimSpace(d.Target), strings.TrimSpace(target)) {
			byKey[d.Key] = d
		}
	}

	r := Review{Target: target, Standard: standard}
	seen := map[string]bool{}
	for _, f := range findings {
		k := key(f)
		if k == "" || seen[k] {
			continue
		}
		seen[k] = true

		it := Item{
			Key: k, FindingID: f.ID, Title: f.Title, Severity: string(f.Severity),
			Endpoint: f.Endpoint, RuleID: f.RuleID, CWE: f.CWE,
			EffectiveSeverity: string(f.Severity),
		}
		it.Confidence = f.Confidence
		it.Rung = string(f.DeriveRung())
		it.Proven = provenRung(it.Rung)

		if d, ok := byKey[k]; ok {
			it.Verdict, it.Reason, it.By, it.Lowered = d.Verdict, d.Reason, d.By, d.Lowered
			if !d.At.IsZero() {
				it.At = d.At.UTC().Format(time.RFC3339)
			}
			if d.Verdict == VerdictReclassify && strings.TrimSpace(d.Severity) != "" {
				it.EffectiveSeverity = d.Severity
			}
		}
		r.Items = append(r.Items, it)
	}

	sort.SliceStable(r.Items, func(i, j int) bool {
		// Undecided first, then the ones the reviewer must supply judgement for, then by severity.
		// The order IS the compression: it puts the expensive minutes at the top.
		a, b := r.Items[i], r.Items[j]
		if (a.Verdict == VerdictPending) != (b.Verdict == VerdictPending) {
			return a.Verdict == VerdictPending
		}
		if a.Proven != b.Proven {
			return !a.Proven
		}
		if sevRank(a.EffectiveSeverity) != sevRank(b.EffectiveSeverity) {
			return sevRank(a.EffectiveSeverity) > sevRank(b.EffectiveSeverity)
		}
		return a.Key < b.Key
	})
	r.Progress = summarize(r.Items)
	return r
}

func summarize(items []Item) Progress {
	p := Progress{Total: len(items)}
	for _, it := range items {
		switch it.Verdict {
		case VerdictInclude:
			p.Included++
			p.Reviewed++
		case VerdictExclude:
			p.Excluded++
			p.Reviewed++
		case VerdictReclassify:
			p.Reclassified++
			p.Reviewed++
		default:
			p.Pending++
		}
		if it.Proven {
			p.Load.Proven++
		} else {
			p.Load.Unproven++
		}
	}
	p.Complete = p.Total > 0 && p.Pending == 0
	p.Load.Detail = loadDetail(p.Load)
	p.Detail = progressDetail(p)
	return p
}

func loadDetail(l Load) string {
	switch {
	case l.Proven+l.Unproven == 0:
		return "Nothing to review."
	case l.Unproven == 0:
		return plural(l.Proven, "finding carries", "findings carry") +
			" evidence a predicate actually produced — you are checking the engine's work, not supplying the proof."
	case l.Proven == 0:
		return plural(l.Unproven, "finding rests", "findings rest") +
			" on a scanner's pattern match alone. Signing these puts your name where the engine could not prove it."
	default:
		return plural(l.Proven, "finding carries", "findings carry") + " evidence a predicate produced, and " +
			plural(l.Unproven, "rests", "rest") +
			" on a pattern match alone — those are the ones your judgement is actually needed for."
	}
}

func progressDetail(p Progress) string {
	switch {
	case p.Total == 0:
		// The empty case is the dangerous one. A review with nothing in it is not a clean application;
		// it is just as likely a scan that never ran, and a certificate issued on it would say the
		// opposite of what is known.
		return "No findings are in scope for this application. That is NOT a completed audit — it is " +
			"an empty one. Confirm a scan actually ran against this target before certifying anything."
	case p.Complete:
		return "Every finding has a decision: " + plural(p.Included, "included", "included") + ", " +
			plural(p.Excluded, "excluded", "excluded") + ", " +
			plural(p.Reclassified, "reclassified", "reclassified") + "."
	default:
		return plural(p.Pending, "finding still needs", "findings still need") +
			" a decision. The report is not signable until every one has been answered."
	}
}

// Decide records one reviewer's verdict. It returns the disposition to store, or an error naming what
// is missing — the refusals are the product, so they are explicit rather than silent.
func Decide(tenantID, target, key string, v Verdict, severity, reason, by string, now time.Time) (Disposition, error) {
	if !v.Valid() {
		return Disposition{}, ErrVerdict
	}
	if strings.TrimSpace(by) == "" {
		// An unattributed decision cannot be audit evidence: the entire point is that a NAMED person
		// stood behind what went into the report.
		return Disposition{}, ErrNoReviewer
	}
	if v.NeedsReason() && strings.TrimSpace(reason) == "" {
		// An exclusion with no reason is indistinguishable from an oversight.
		return Disposition{}, ErrNoReason
	}
	d := Disposition{
		TenantID: tenantID, Target: strings.TrimSpace(target), Key: key, Verdict: v,
		Reason: strings.TrimSpace(reason), By: strings.TrimSpace(by), At: now.UTC(),
	}
	if v == VerdictReclassify {
		if !validSeverity(severity) {
			return Disposition{}, ErrSeverity
		}
		d.Severity = strings.ToLower(strings.TrimSpace(severity))
	}
	return d, nil
}

// MarkDirection records whether a reclassification lowered the severity, which Decide cannot know
// without the engine's original. Separate so the caller supplies the fact rather than the package
// guessing at it.
func MarkDirection(d Disposition, engineSeverity string) Disposition {
	if d.Verdict == VerdictReclassify {
		d.Lowered = sevRank(d.Severity) < sevRank(engineSeverity)
	}
	return d
}

func provenRung(rung string) bool {
	switch types.EvidenceRung(rung) {
	case types.RungExploited, types.RungProviderConfirmed, types.RungReachabilityConfirmed:
		return true
	}
	return false
}

var sevOrder = map[string]int{"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}

func sevRank(s string) int { return sevOrder[strings.ToLower(strings.TrimSpace(s))] }

func validSeverity(s string) bool { return sevRank(s) > 0 }

func plural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return itoa(n) + " " + many
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

// The refusals, named. They are returned rather than silently coerced because each one is a case
// where accepting the input would put something unsupportable into a signed document.
var (
	// ErrVerdict — not one of the three decisions a reviewer may take.
	ErrVerdict = errors.New(`verdict must be "include", "exclude" or "reclassify"`)
	// ErrNoReviewer — an audit record with no named human is a log line.
	ErrNoReviewer = errors.New("name the reviewer taking this decision")
	// ErrNoReason — removing a finding from a signed report, or changing its severity, is the
	// reviewer's own claim and must say why.
	ErrNoReason = errors.New("a reason is required to exclude or reclassify a finding")
	// ErrSeverity — a reclassification with no valid severity changes nothing and would silently
	// leave the engine's.
	ErrSeverity = errors.New("reclassifying needs a severity: critical, high, medium, low or info")
)
