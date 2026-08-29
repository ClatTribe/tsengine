package platform

import "time"

// The Trust Center's persisted shapes — the buyer-facing half of the product.
//
// A trust page turns the security review from a call someone has to schedule into a link
// they can read alone, which is the single most common reason a deal sits still. The
// category (SafeBase, Vanta Trust Center, Drata Trust Center) settled on one arrangement:
// a public tier anyone may read, a gated tier behind an NDA and an approval, and a log of
// who looked at what.
//
// WHAT MAKES OURS DIFFERENT, AND WHAT THAT OBLIGES. Everyone else hosts a PDF somebody
// uploaded; the reader has to trust that it still describes the company. Our documents are
// GENERATED from the same grounded posture the customer sees in-app, so they cannot go
// stale — and that is exactly why the honesty rules here are stricter than the category's,
// not looser. This is the most expensive page in the product to overstate anything on: the
// reader is doing vendor due diligence on someone who trusted us to describe them
// accurately, and unlike an in-app screen there is no context around it to correct a wrong
// impression.
//
// Three refusals fall out of that, each enforced in internal/trustcenter rather than left
// to whoever configures the page:
//
//  1. A document whose body names open findings can never be PUBLIC (DocKind.MinVisibility).
//     internal/platformapi/trust.go already refuses to publish which controls are gaps,
//     because a gap list is an attacker's roadmap; a VAPT report is that same list with
//     reproduction steps attached. An owner is one click away from publishing it, so the
//     click has to be unavailable rather than merely discouraged.
//  2. A document is listed only when it can actually be produced. A locked "SOC 2 Report"
//     row on a page that has no such report asserts that one exists.
//  3. What a buyer accepted is recorded as an artifact, not as a boolean. See NDAHash.

// Visibility is who may read a Trust Center document.
type Visibility string

const (
	// VisPublic — served to anyone holding the tenant's Trust Center link.
	VisPublic Visibility = "public"
	// VisGated — served only after an approved access request, with the NDA accepted and
	// the grant unexpired.
	VisGated Visibility = "gated"
	// VisPrivate — not served, and not listed. The off switch for a document the tenant
	// configured but does not currently want offered. Distinct from deleting it, so a
	// document can be withdrawn without losing its configuration.
	VisPrivate Visibility = "private"
)

// DocKind identifies what a Trust Center document IS, which decides both how it is produced
// and the strongest visibility it may be given.
type DocKind string

const (
	// DocOverview is the posture summary — per-framework assessment coverage. Aggregate by
	// construction: it says how much has been assessed, never which controls are gaps.
	DocOverview DocKind = "overview"
	// DocQuestionnaire is the auto-answered CAIQ/SIG-lite set (internal/grc/questionnaire.go).
	// Attestations about controls, not a list of what is broken.
	DocQuestionnaire DocKind = "questionnaire"
	// DocSubprocessors is the vendor/sub-processor inventory (internal/tprm). The one document
	// on this page that regulation expects to be public: GDPR Art. 28 sub-processor disclosure.
	DocSubprocessors DocKind = "subprocessors"
	// DocPolicies is the published security policy set (internal/grc/program.go) — titles,
	// owners, and publication dates. The bodies are the tenant's to share; what a buyer asks
	// first is whether the policies exist and who owns them.
	DocPolicies DocKind = "policies"
	// DocComplianceReport is the per-framework report — every gap control and the findings
	// citing it. NEVER public.
	DocComplianceReport DocKind = "compliance_report"
	// DocVAPTReport is the penetration-test report — findings, severities, endpoints, and for
	// exploitation-proven ones the reproduction. NEVER public.
	DocVAPTReport DocKind = "vapt_report"
	// DocEvidencePack is the signed evidence bundle. Its value is that a buyer's own reviewer
	// can verify the signature rather than trust a logo — but it carries the findings that
	// back each control, so it is gated like the reports. NEVER public.
	DocEvidencePack DocKind = "evidence_pack"
	// DocExternal is a link to a document we do not produce — the auditor's SOC 2 Type II
	// report, an ISO certificate, a signed DPA. We host no files, so this is a URL the tenant
	// supplies and we gate access to. NEVER public: the whole reason to route an auditor's
	// report through here is that it should not be an open link.
	DocExternal DocKind = "external"
)

// MinVisibility is the WEAKEST gate a kind may be given — the structural half of refusal (1)
// above. Returning VisGated means public is not an option the product offers, however the
// config arrived: through the API, through a hand-edited store file, or through a future UI
// that forgets to disable the control.
//
// The line is drawn at whether the document's BODY names open findings. Coverage percentages,
// questionnaire answers, sub-processor names and policy titles do not. A compliance report, a
// VAPT report and an evidence pack do — they are the artifact an attacker would most like to
// be handed, which is also precisely why a buyer wants them, so the answer is to gate them
// rather than to withhold them.
func (k DocKind) MinVisibility() Visibility {
	switch k {
	case DocComplianceReport, DocVAPTReport, DocEvidencePack, DocExternal:
		return VisGated
	default:
		return VisPublic
	}
}

// Generated reports whether the platform produces this document's body from live posture, as
// opposed to pointing at something the tenant hosts elsewhere. Rendered to the buyer, because
// "generated from posture on the date you opened it" and "a PDF uploaded at some point" are
// different claims and the reader cannot otherwise tell them apart.
func (k DocKind) Generated() bool { return k != DocExternal }

// TrustDocument is one row on the Trust Center.
type TrustDocument struct {
	Kind       DocKind    `json:"kind"`
	Title      string     `json:"title,omitempty"` // display override; the kind's default is used when empty
	Visibility Visibility `json:"visibility"`
	// Framework scopes a per-framework document (DocComplianceReport, DocEvidencePack) to one
	// framework key. Ignored by kinds that have no framework.
	Framework string `json:"framework,omitempty"`
	// URL is where a DocExternal points. Ignored by generated kinds — a generated document has
	// no URL to trust, and accepting one would let a config silently redirect a buyer away from
	// the posture the page claims to be showing.
	URL string `json:"url,omitempty"`
	// Note is the tenant's own one-line context ("Type II, period ending March 2026").
	Note string `json:"note,omitempty"`
}

// TrustCenterConfig is the tenant's Trust Center settings. It lives on the Tenant rather than
// in its own store entity for the same reason SLA, Escalation and Contacts do: it is
// configuration, there is exactly one per tenant, and it carries no secret.
type TrustCenterConfig struct {
	Enabled bool `json:"enabled"`
	// TokenVersion is folded into the share-link MAC so a leaked link can be killed by bumping
	// it. Before this existed the token was a bare HMAC over the tenant id, which made it
	// PERMANENT: the only way to invalidate one was rotating the platform secret, taking every
	// other tenant's link — and, since that secret also keys OAuth state, rather more than that
	// — down with it. The public page told readers a link "has been revoked", which nothing in
	// the product could bring about.
	//
	// 0 and 1 are the same token, so existing links keep working across the upgrade.
	TokenVersion int `json:"token_version,omitempty"`
	// Headline is the one line under the org name. Empty renders the default.
	Headline string `json:"headline,omitempty"`
	// ContactEmail is where a buyer's questions go when the page cannot answer them.
	ContactEmail string `json:"contact_email,omitempty"`
	// Documents is what the page offers. Order is display order.
	Documents []TrustDocument `json:"documents,omitempty"`
	// NDAText is the click-through agreement a buyer accepts before a gated document unlocks.
	// Empty means no NDA is required — a deliberate choice a tenant may make, not a default we
	// pick for them.
	NDAText string `json:"nda_text,omitempty"`
	// AutoApproveDomains are email domains whose requests are approved without a human, e.g.
	// ["acme.com"]. The category calls this "instant access for known buyers"; it is a real
	// convenience and a real delegation, so it is opt-in and per-domain. A wildcard is refused
	// (internal/trustcenter.NormalizeConfig) — "auto-approve everyone" is publishing, and
	// should be done by setting a document public rather than by a rule that hides the fact.
	AutoApproveDomains []string `json:"auto_approve_domains,omitempty"`
	// Subprocessors is the sub-processor disclosure — the one document on this page that
	// regulation expects to be public (GDPR Art. 28), and the one a buyer's counsel reads
	// rather than their engineer.
	//
	// It is AUTHORED here rather than derived from internal/tprm, and that is a deliberate
	// correction to the obvious design. tprm ingests a vendor inventory and persists only the
	// FINDINGS it raises — so a list derived from stored state would name the vendors that
	// failed a check and omit every well-managed one, publishing "our problematic suppliers"
	// under the heading "our sub-processors". Beyond being wrong, it is the wrong KIND of
	// artifact: a sub-processor disclosure is a legal statement the company makes, not an
	// inference a risk tool draws.
	Subprocessors []Subprocessor `json:"subprocessors,omitempty"`
	// GrantTTLHours bounds how long an approved buyer keeps access. 0 resolves to the package
	// default rather than to "forever" — an unbounded grant is the same permanence bug as the
	// un-revocable share link, one level in.
	GrantTTLHours int `json:"grant_ttl_hours,omitempty"`
}

// Subprocessor is one third party that processes customer data on the tenant's behalf.
// Purpose and Location are what a GDPR Art. 28 disclosure is actually for — a reader needs to
// know what the vendor does and which jurisdiction the data lands in, not just its name.
type Subprocessor struct {
	Name     string `json:"name"`
	Purpose  string `json:"purpose,omitempty"`
	Location string `json:"location,omitempty"`
	URL      string `json:"url,omitempty"`
}

// Access-request lifecycle.
const (
	TrustReqPending  = "pending"
	TrustReqApproved = "approved"
	TrustReqDenied   = "denied"
)

// TrustAccessRequest is one buyer's request to read the gated tier, and the record of what
// happened to it. Append-only in spirit: a denied or expired request is kept, because "nobody
// ever asked" and "we said no" are different facts about a deal.
type TrustAccessRequest struct {
	ID       string `json:"id"`
	TenantID string `json:"tenant_id"`
	// Email, Name, Company are what the buyer typed. Unverified by construction — we do not
	// send a confirmation mail — so they are treated as a claim about who is asking, never as
	// authentication. What actually gates access is TokenHash.
	Email   string `json:"email"`
	Name    string `json:"name,omitempty"`
	Company string `json:"company,omitempty"`
	Reason  string `json:"reason,omitempty"`

	Status      string    `json:"status"`
	RequestedAt time.Time `json:"requested_at"`
	DecidedAt   time.Time `json:"decided_at,omitzero"`
	// DecidedBy names the human who approved or denied, or is the empty string when an
	// AutoApproveDomains rule did it. The distinction is kept rather than filling in a
	// plausible name: a decision nobody made should not read as one somebody made.
	DecidedBy string `json:"decided_by,omitempty"`
	// AutoApproved records that a rule decided this, so the log can show which grants had a
	// human behind them.
	AutoApproved bool `json:"auto_approved,omitempty"`

	// TokenHash is the SHA-256 of the access token handed to the buyer. The token itself is
	// shown once, at approval, and never stored — the same treatment the password-reset flow
	// gives its link, and for the same reason: a store dump must not yield working access.
	TokenHash string    `json:"token_hash,omitempty"`
	ExpiresAt time.Time `json:"expires_at,omitzero"`
	// Revoked ends a grant early, ahead of its expiry.
	Revoked bool `json:"revoked,omitempty"`

	// NDAAcceptedAt and NDAHash record the acceptance. The HASH is the point: "they accepted an
	// NDA" is worth nothing later if we cannot say WHICH text, and the text is editable
	// configuration. Storing the digest of what was on screen at acceptance makes the claim
	// checkable — the same instinct as pinning a corpus version into a scan's evidence.
	NDAAcceptedAt time.Time `json:"nda_accepted_at,omitzero"`
	NDAHash       string    `json:"nda_hash,omitempty"`
	NDAName       string    `json:"nda_name,omitempty"` // who typed their name on the acceptance

	// Views is the append-only access log — what this buyer opened and when. It is the security
	// record for a document set that leaves the building, and separately the strongest sales
	// signal the product can emit: the prospect just read the pentest report.
	Views []TrustView `json:"views,omitempty"`
}

// TrustView is one document open by one granted buyer.
type TrustView struct {
	At        time.Time `json:"at"`
	Kind      DocKind   `json:"kind"`
	Framework string    `json:"framework,omitempty"`
}

// Granted reports whether this request currently entitles its holder to the gated tier.
//
// Every condition is checked here rather than at the call sites, because there are several
// call sites and a gate re-implemented per handler is a gate that will eventually disagree
// with itself. An NDA is required only when the tenant configured one; the caller passes what
// the config says rather than this type guessing.
func (r TrustAccessRequest) Granted(ndaRequired bool, now time.Time) bool {
	if r.Status != TrustReqApproved || r.Revoked {
		return false
	}
	if !r.ExpiresAt.IsZero() && !now.Before(r.ExpiresAt) {
		return false
	}
	if ndaRequired && r.NDAAcceptedAt.IsZero() {
		return false
	}
	return true
}
