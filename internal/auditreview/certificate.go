package auditreview

import (
	"sort"
	"strings"
	"time"
)

// certificate.go produces the artifact the buyer is actually purchasing.
//
// In the GeM tenders this product targets, the deliverable is a Safe-to-Host / Web Security Audit
// certificate, and it is what lets the buyer host on government infrastructure. That makes it the
// most consequential document this codebase emits: a customer forwards it to a third party who
// relies on it, and nobody downstream can see what it was based on.
//
// So it is REFUSED more readily than anything else here. Certify returns blockers instead of a
// certificate whenever issuing one would assert something unsupported, and the blockers name what to
// fix rather than failing blankly.

// Certificate is the signed statement. Deliberately short: a certificate asserts a small number of
// things precisely, and the report carries the detail.
type Certificate struct {
	Target   string `json:"target"`
	Standard string `json:"standard,omitempty"` // e.g. "OWASP Top 10 (2021)"
	// Auditor is the named human and their firm. Capacity (internal | msp | managed) is resolved
	// from the practitioner roster by the caller, never typed into a form — the same rule the rest
	// of the HITL artifacts follow.
	Auditor  string    `json:"auditor"`
	Firm     string    `json:"firm,omitempty"`
	Capacity string    `json:"capacity,omitempty"`
	IssuedAt time.Time `json:"issued_at"`

	// What the audit actually examined and concluded.
	FindingsReviewed int            `json:"findings_reviewed"`
	Included         int            `json:"included"`
	Excluded         int            `json:"excluded"`
	OpenBySeverity   map[string]int `json:"open_by_severity,omitempty"`

	// NotTested is the coverage the audit did NOT cover, stated on the certificate itself rather
	// than buried in an appendix. A certificate that lists only what was checked reads as though
	// everything was, which is the same green-tick-on-unscanned-scope overclaim the coverage layer
	// exists to prevent — and here it would be asserted to a government buyer.
	NotTested []string `json:"not_tested,omitempty"`

	// Statement is the sentence the auditor is signing. Generated so it cannot quietly say more
	// than the evidence supports; see statement().
	Statement string `json:"statement"`

	// Engine is provenance and is NEVER white-labelled, matching VAPTReport.Engine: a reader
	// re-running a finding needs to know what produced it, and the firm's brand on the prose does
	// not change what ran.
	Engine string `json:"engine,omitempty"`
}

// Blocker is one reason a certificate cannot be issued yet.
type Blocker struct {
	Kind   string `json:"kind"`
	Detail string `json:"detail"`
}

// CertifyOptions is the firm's own bar. Different empanelled firms certify against different
// policies, so the threshold is theirs — but it can never be silent: whatever it is set to, an
// unresolved finding at or above it blocks, and the certificate states what remained open.
type CertifyOptions struct {
	Standard string
	Auditor  string
	Firm     string
	Capacity string
	// BlockAtOrAbove is the severity at which an INCLUDED, unresolved finding prevents issue.
	// Empty means "critical" — the most permissive defensible default, never "none".
	BlockAtOrAbove string
	// NotTested is the coverage disclosure for this target, supplied by the caller from the scan's
	// own declared gaps. Empty is allowed and means the caller had nothing to declare — it does NOT
	// mean everything was tested, which is why the statement never says so.
	NotTested []string
	// Resolved marks finding keys a re-test proved closed. The tender flow is draft → remediate →
	// re-test → final → certificate, so by issue time the serious ones should be here.
	Resolved map[string]bool
}

// Certify issues the certificate, or returns every reason it cannot.
//
// Returns ALL blockers rather than the first, because a reviewer fixing them one at a time and
// re-submitting is exactly the slow loop this product exists to remove.
func Certify(r Review, opt CertifyOptions, now time.Time) (*Certificate, []Blocker) {
	var blockers []Blocker

	if strings.TrimSpace(opt.Auditor) == "" {
		blockers = append(blockers, Blocker{"no_auditor",
			"No named auditor. A certificate with no name on it is not an attestation — someone has to be accountable for it."})
	}
	if r.Progress.Total == 0 {
		// The empty audit. Worth its own blocker rather than falling out of "nothing pending",
		// because zero findings and zero decisions would otherwise read as a completed clean audit.
		blockers = append(blockers, Blocker{"empty_scope",
			"No findings are in scope for this application. An audit that examined nothing cannot certify anything — " +
				"confirm a scan actually ran against this target."})
	} else if !r.Progress.Complete {
		blockers = append(blockers, Blocker{"undecided",
			plural(r.Progress.Pending, "finding has", "findings have") +
				" no decision yet. Every finding must be answered before the report can be signed."})
	}

	floor := strings.ToLower(strings.TrimSpace(opt.BlockAtOrAbove))
	if floor == "" {
		floor = "critical"
	}
	open := map[string]int{}
	var unresolved []string
	for _, it := range r.Items {
		if it.Verdict == VerdictExclude {
			continue // excluded findings are not part of what this certificate asserts
		}
		if opt.Resolved[it.Key] {
			continue
		}
		sev := strings.ToLower(it.EffectiveSeverity)
		open[sev]++
		if sevRank(sev) >= sevRank(floor) && sevRank(sev) > 0 {
			unresolved = append(unresolved, it.Title)
		}
	}
	if len(unresolved) > 0 {
		sort.Strings(unresolved)
		blockers = append(blockers, Blocker{"unresolved",
			plural(len(unresolved), "finding is", "findings are") + " open at or above " + floor +
				" and no re-test has shown them closed: " + strings.Join(unresolved, "; ") + "."})
	}

	if len(blockers) > 0 {
		return nil, blockers
	}

	c := &Certificate{
		Target: r.Target, Standard: opt.Standard,
		Auditor: strings.TrimSpace(opt.Auditor), Firm: strings.TrimSpace(opt.Firm),
		Capacity: opt.Capacity, IssuedAt: now.UTC(),
		FindingsReviewed: r.Progress.Total,
		Included:         r.Progress.Included + r.Progress.Reclassified,
		Excluded:         r.Progress.Excluded,
		NotTested:        append([]string(nil), opt.NotTested...),
	}
	if len(open) > 0 {
		c.OpenBySeverity = open
	}
	c.Statement = statement(c, floor)
	return c, nil
}

// statement writes the sentence the auditor signs.
//
// It is GENERATED rather than typed for one reason: a free-text box is where "no vulnerabilities
// were found" gets written about an audit that excluded four findings and never tested the API. The
// generated sentence can only say what the review actually established, and it always names the
// limits — what remained open, what was excluded, and what was not tested.
func statement(c *Certificate, floor string) string {
	var b strings.Builder
	b.WriteString("This certifies that ")
	b.WriteString(c.Target)
	if c.Standard != "" {
		b.WriteString(" was assessed against ")
		b.WriteString(c.Standard)
	} else {
		b.WriteString(" was assessed")
	}
	b.WriteString(" on ")
	b.WriteString(c.IssuedAt.Format("2 January 2006"))
	b.WriteString(". ")

	b.WriteString(plural(c.FindingsReviewed, "finding was", "findings were"))
	b.WriteString(" reviewed")
	if c.Excluded > 0 {
		// Stated, not hidden. An excluded finding is a reviewer's judgement, and a reader of the
		// certificate is entitled to know judgement was exercised and how often.
		b.WriteString(", of which ")
		b.WriteString(itoa(c.Excluded))
		b.WriteString(" were assessed as not applicable to this application and excluded with reasons recorded")
	}
	b.WriteString(". ")

	if n := openAtOrAbove(c.OpenBySeverity, floor); n > 0 {
		b.WriteString(plural(n, "finding remains", "findings remain"))
		b.WriteString(" open at or above ")
		b.WriteString(floor)
		b.WriteString(". ")
	} else {
		b.WriteString("No findings remain open at or above ")
		b.WriteString(floor)
		b.WriteString(" as at the date above. ")
	}

	if len(c.NotTested) > 0 {
		b.WriteString("Not covered by this assessment: ")
		b.WriteString(strings.Join(c.NotTested, "; "))
		b.WriteString(". ")
	}

	// The limit every certificate carries. It is a statement about a point in time and a defined
	// scope, and saying so is what stops it being read as a guarantee of security.
	b.WriteString("This assessment reflects the state of the application within the scope above at the date of issue; " +
		"it is not a guarantee that the application is free of vulnerabilities.")
	return b.String()
}

func openAtOrAbove(open map[string]int, floor string) int {
	n := 0
	for sev, count := range open {
		if sevRank(sev) >= sevRank(floor) && sevRank(sev) > 0 {
			n += count
		}
	}
	return n
}
