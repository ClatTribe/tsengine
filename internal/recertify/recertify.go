// Package recertify runs a periodic access review — the attestation half of the access-control
// story, which the product could detect but never asked anyone to complete.
//
// # The gap this closes
//
// `operate` already finds the accounts that matter: someone who has not logged in for months but is
// still active, an admin without MFA, a suspended account that still holds a privileged role binding.
// That is the DETECTION half, and it is good.
//
// The ATTESTATION half was missing entirely. SOC 2 CC6.2 and CC6.3 do not ask whether you can detect
// stale access; they ask whether you periodically REVIEW who has access and record the outcome. An
// auditor wants a named person saying "yes, this individual still needs this" or "no, remove it", on
// a date, with evidence. The platform had every piece needed to run that — findings, named-human
// attestation, a signed ledger — and nobody was ever asked, so it did not happen.
//
// # A review is a DECISION, not an action
//
// Deciding that access should be revoked does not revoke it here. The decision is recorded, and
// acting on it goes through the same remediation and approval path as everything else (§18.2 inv. 3).
// Collapsing those would mean a review click silently mutating a customer's identity provider, which
// is exactly the kind of authority this product deliberately does not take.
//
// # Grounding (§10)
//
// A campaign covers the identities we can actually see, and says so. With no identity provider
// connected there is nothing to review, and the campaign reports that rather than completing
// vacuously — "0 of 0 reviewed, complete" would be an audit artifact asserting a review that never
// examined anyone, which is worse than having no artifact at all.
package recertify

import (
	"sort"
	"strings"
	"time"

	"github.com/ClatTribe/tsengine/pkg/types"
)

// Decision is a reviewer's verdict on one person's access.
type Decision string

const (
	// DecisionPending is the zero value — nobody has reviewed this identity yet.
	DecisionPending Decision = ""
	// DecisionKeep says the access is still required for the person's job.
	DecisionKeep Decision = "keep"
	// DecisionRevoke says it is not. Recording this does NOT revoke anything; it produces a
	// remediation the normal gate has to approve.
	DecisionRevoke Decision = "revoke"
)

func (d Decision) Valid() bool { return d == DecisionKeep || d == DecisionRevoke }

// Identity is one account under review, with the reasons it was flagged.
type Identity struct {
	// Subject is the account — an email address as the IdP reports it.
	Subject string `json:"subject"`
	// Reasons are the findings that put this account in the review, in the reviewer's words. A
	// reviewer deciding blind is not reviewing; they are guessing.
	Reasons []string `json:"reasons"`
	// FindingIDs back the reasons, so a decision can be traced to the evidence that prompted it.
	FindingIDs []string `json:"finding_ids"`
	// Severity is the worst severity among the reasons, so the list leads with what matters.
	Severity types.Severity `json:"severity"`

	Decision  Decision `json:"decision"`
	DecidedBy string   `json:"decided_by,omitempty"`
	DecidedAt string   `json:"decided_at,omitempty"`
	Note      string   `json:"note,omitempty"`
}

// Campaign is one round of review.
type Campaign struct {
	ID         string     `json:"id"`
	TenantID   string     `json:"tenant_id"`
	OpenedAt   time.Time  `json:"opened_at"`
	ClosedAt   *time.Time `json:"closed_at,omitempty"`
	Identities []Identity `json:"identities"`
}

// recertRules are the finding rules that put an account into a review. Deliberately narrow: a review
// that includes every finding about a person becomes a second findings list, and reviewers stop
// reading it. These are the ones where the question "does this person still need this?" is the
// actual remedy.
var recertRules = []string{
	"operate::stale-account",
	"operate::incomplete-offboarding",
	"operate::admin-no-mfa",
	"operate::admin-without-mfa",
	"operate::over-privileged",
	"operate::super-admin",
}

// Build assembles a campaign from the tenant's current identity findings.
//
// Returns the campaign and whether there was anything to review. An EMPTY campaign is not an
// achievement and must not be presented as one — see the package comment.
func Build(id, tenantID string, findings []types.Finding, now time.Time) (Campaign, bool) {
	bySubject := map[string]*Identity{}
	for _, f := range findings {
		if !isRecertFinding(f) {
			continue
		}
		subj := strings.TrimSpace(f.Endpoint)
		if subj == "" {
			// A finding that does not name WHO cannot be reviewed by a human — there is nobody to
			// decide about. Dropping it is right; counting it would inflate the campaign with rows
			// no reviewer can action.
			continue
		}
		cur, ok := bySubject[subj]
		if !ok {
			cur = &Identity{Subject: subj}
			bySubject[subj] = cur
		}
		cur.Reasons = append(cur.Reasons, reasonFor(f))
		cur.FindingIDs = append(cur.FindingIDs, f.ID)
		if worse(f.Severity, cur.Severity) {
			cur.Severity = f.Severity
		}
	}

	c := Campaign{ID: id, TenantID: tenantID, OpenedAt: now}
	for _, v := range bySubject {
		c.Identities = append(c.Identities, *v)
	}
	sort.SliceStable(c.Identities, func(i, j int) bool {
		if c.Identities[i].Severity != c.Identities[j].Severity {
			return worse(c.Identities[i].Severity, c.Identities[j].Severity)
		}
		return c.Identities[i].Subject < c.Identities[j].Subject
	})
	return c, len(c.Identities) > 0
}

func isRecertFinding(f types.Finding) bool {
	for _, r := range recertRules {
		if strings.HasPrefix(f.RuleID, r) {
			return true
		}
	}
	return false
}

// reasonFor renders the finding as the question a reviewer is actually answering.
func reasonFor(f types.Finding) string {
	if t := strings.TrimSpace(f.Title); t != "" {
		return t
	}
	return f.RuleID
}

var sevRank = map[types.Severity]int{
	types.SeverityCritical: 4, types.SeverityHigh: 3,
	types.SeverityMedium: 2, types.SeverityLow: 1, types.SeverityInfo: 0,
}

func worse(a, b types.Severity) bool { return sevRank[a] > sevRank[b] }

// Progress is the honest state of a campaign.
type Progress struct {
	Total    int `json:"total"`
	Reviewed int `json:"reviewed"`
	Keep     int `json:"keep"`
	Revoke   int `json:"revoke"`
	Pending  int `json:"pending"`
	// Complete is true only when EVERY identity has a decision. A partly-finished review is not a
	// review, and an auditor asking "did you complete the access review" needs this to be false
	// until it genuinely is.
	Complete bool `json:"complete"`
}

// Summarize counts the decisions.
func Summarize(c Campaign) Progress {
	p := Progress{Total: len(c.Identities)}
	for _, i := range c.Identities {
		switch i.Decision {
		case DecisionKeep:
			p.Keep++
			p.Reviewed++
		case DecisionRevoke:
			p.Revoke++
			p.Reviewed++
		default:
			p.Pending++
		}
	}
	// An empty campaign is NOT complete. "0 of 0 reviewed, complete" is an audit artifact asserting a
	// review that examined nobody — worse than no artifact, because it would be filed as evidence.
	p.Complete = p.Total > 0 && p.Pending == 0
	return p
}

// Decide records a reviewer's verdict. Returns false if the subject is not in the campaign or the
// verdict is not one a reviewer may give.
func Decide(c *Campaign, subject string, d Decision, by, note string, now time.Time) bool {
	if !d.Valid() || strings.TrimSpace(by) == "" {
		// An unattributed decision cannot be audit evidence: the whole point is that a NAMED person
		// stood behind it.
		return false
	}
	for i := range c.Identities {
		if c.Identities[i].Subject != subject {
			continue
		}
		c.Identities[i].Decision = d
		c.Identities[i].DecidedBy = strings.TrimSpace(by)
		c.Identities[i].DecidedAt = now.UTC().Format(time.RFC3339)
		c.Identities[i].Note = strings.TrimSpace(note)
		return true
	}
	return false
}

// Revocations lists the subjects a reviewer said should lose access, so the caller can propose the
// removals through the normal remediation gate. This package never acts on them itself.
func Revocations(c Campaign) []Identity {
	var out []Identity
	for _, i := range c.Identities {
		if i.Decision == DecisionRevoke {
			out = append(out, i)
		}
	}
	return out
}
