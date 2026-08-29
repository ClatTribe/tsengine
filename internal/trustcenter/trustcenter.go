// Package trustcenter is the decision layer behind the buyer-facing Trust Center: which
// documents a given visitor may see, who is granted access, and what they accepted to get it.
//
// It is deliberately pure — no store, no HTTP, no clock of its own. Every rule here is a
// decision that has to hold identically at three call sites (the public page, the document
// fetch, the owner's config save), and a rule re-derived per handler is one that will
// eventually disagree with itself. The handlers in internal/platformapi supply the facts;
// this package decides.
//
// The refusals it enforces are documented on pkg/platform's trust types. Two of them are
// worth restating here because they are what the code in this file is mostly doing:
//
//   - A document is offered only when it can actually be produced (Catalog drops anything the
//     caller reports unavailable). A greyed-out "SOC 2 Report" row is an assertion that such a
//     report exists, made to the reader least able to check it.
//   - A document whose body names open findings cannot be made public, whatever the config
//     says (NormalizeConfig clamps, and records that it did).
package trustcenter

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/ClatTribe/tsengine/pkg/platform"
)

// DefaultGrantTTL bounds an approved buyer's access when the tenant sets no explicit window.
//
// Thirty days is the category's usual default and long enough to clear a procurement cycle
// without a second round-trip. The value matters less than the fact that there IS one: a grant
// with no expiry is the same permanence defect as a share link with no revocation, and both
// end the same way — access nobody remembers issuing, outliving the deal it was for.
const DefaultGrantTTL = 30 * 24 * time.Hour

// MaxGrantTTL caps what a tenant may configure. A year-long grant to a document set that
// regenerates from live posture means a buyer keeps reading the company's current security
// state long after the evaluation ended.
const MaxGrantTTL = 365 * 24 * time.Hour

// Correction is one change NormalizeConfig made to a submitted config, so the caller can tell
// the owner what happened. A config silently altered on save is a config the owner believes
// says something it does not — which on this page means believing a document is private when
// it is published, or public when it is gated.
type Correction struct {
	Field  string `json:"field"`
	Reason string `json:"reason"`
}

// NormalizeConfig validates and repairs a submitted Trust Center config, returning the config
// that will actually be stored plus every correction it had to make.
//
// It repairs rather than rejects, with one exception (see the URL handling below). An owner
// configuring a share page should not have their whole submission bounced because one document
// asked for a gate the product does not offer; they should get the config they can have, and be
// told which part was changed.
func NormalizeConfig(in platform.TrustCenterConfig) (platform.TrustCenterConfig, []Correction) {
	out := in
	var corr []Correction

	out.Headline = strings.TrimSpace(out.Headline)
	out.ContactEmail = strings.TrimSpace(out.ContactEmail)
	out.NDAText = strings.TrimSpace(out.NDAText)

	// TTL: 0 means "unset" and resolves to the default, never to unbounded.
	switch {
	case out.GrantTTLHours < 0:
		out.GrantTTLHours = int(DefaultGrantTTL / time.Hour)
		corr = append(corr, Correction{"grant_ttl_hours", "a negative access window is not a window; reset to the default"})
	case out.GrantTTLHours == 0:
		out.GrantTTLHours = int(DefaultGrantTTL / time.Hour)
	case time.Duration(out.GrantTTLHours)*time.Hour > MaxGrantTTL:
		out.GrantTTLHours = int(MaxGrantTTL / time.Hour)
		corr = append(corr, Correction{"grant_ttl_hours", "capped at one year: these documents regenerate from live posture, so a longer grant keeps a stranger reading your current security state"})
	}

	// Auto-approve domains: lower-cased, de-duped, and never a wildcard.
	//
	// "*" would auto-approve the internet, which is publishing — but publishing that LOOKS
	// like an access-controlled page, complete with an approval log full of names nobody
	// checked. A tenant who wants a document open should set that document public, where the
	// consequence is legible.
	seenDomain := map[string]bool{}
	domains := out.AutoApproveDomains[:0:0]
	for _, d := range out.AutoApproveDomains {
		d = strings.ToLower(strings.TrimSpace(strings.TrimPrefix(d, "@")))
		if d == "" {
			continue
		}
		if d == "*" || strings.Contains(d, "*") {
			corr = append(corr, Correction{"auto_approve_domains", "wildcard removed: auto-approving every domain is publishing, so set the document public instead — that way the page says so"})
			continue
		}
		if !strings.Contains(d, ".") {
			corr = append(corr, Correction{"auto_approve_domains", fmt.Sprintf("%q is not a domain", d)})
			continue
		}
		if seenDomain[d] {
			continue
		}
		seenDomain[d] = true
		domains = append(domains, d)
	}
	out.AutoApproveDomains = domains

	// Sub-processors: a name is the minimum a disclosure needs, so an entry without one is
	// dropped rather than rendered as a blank row on a page someone's counsel is reading.
	subs := out.Subprocessors[:0:0]
	for _, s := range out.Subprocessors {
		s.Name = strings.TrimSpace(s.Name)
		s.Purpose = strings.TrimSpace(s.Purpose)
		s.Location = strings.TrimSpace(s.Location)
		s.URL = strings.TrimSpace(s.URL)
		if s.Name == "" {
			corr = append(corr, Correction{"subprocessors", "an entry with no name was dropped"})
			continue
		}
		if s.URL != "" && validExternalURL(s.URL) != nil {
			corr = append(corr, Correction{"subprocessors", fmt.Sprintf("%s: link dropped, it must be https", s.Name)})
			s.URL = ""
		}
		subs = append(subs, s)
	}
	out.Subprocessors = subs

	seenDoc := map[string]bool{}
	docs := out.Documents[:0:0]
	for _, d := range out.Documents {
		d.Title = strings.TrimSpace(d.Title)
		d.Note = strings.TrimSpace(d.Note)
		d.Framework = strings.TrimSpace(d.Framework)
		d.URL = strings.TrimSpace(d.URL)

		if d.Kind == "" {
			corr = append(corr, Correction{"documents", "a document with no kind was dropped"})
			continue
		}
		key := DocumentKey(d)
		if seenDoc[key] {
			corr = append(corr, Correction{"documents", fmt.Sprintf("%s listed twice; kept the first", key)})
			continue
		}
		seenDoc[key] = true

		if d.Visibility == "" {
			d.Visibility = platform.VisGated
		}

		if d.Kind.Generated() {
			// A generated document has no URL to honour. Accepting one would let a config
			// point the buyer at a page of someone else's choosing while the row still
			// carries our "generated from live posture" label — the reader would have no way
			// to tell they had been redirected away from the thing the label describes.
			if d.URL != "" {
				corr = append(corr, Correction{"documents", fmt.Sprintf("%s is generated from your posture, so its link was dropped", d.Kind)})
				d.URL = ""
			}
		} else if err := validExternalURL(d.URL); err != nil {
			// The one hard rejection: an external row with no usable link is a row that
			// promises a document and delivers nothing. Repairing it is not possible —
			// there is nothing to repair it TO — so it is dropped and named.
			corr = append(corr, Correction{"documents", fmt.Sprintf("%s dropped: %v", d.Kind, err)})
			continue
		}

		if v, clamped, why := ClampVisibility(d.Kind, d.Visibility); clamped {
			corr = append(corr, Correction{"documents", fmt.Sprintf("%s: %s", d.Kind, why)})
			d.Visibility = v
		} else {
			d.Visibility = v
		}
		docs = append(docs, d)
	}
	out.Documents = docs
	return out, corr
}

// validExternalURL requires an absolute https URL.
//
// http is refused rather than upgraded. The tenant is sending a buyer's security reviewer to
// read an auditor's report; handing them a link that can be read and rewritten in transit is
// the wrong thing to do quietly, and guessing that the https version exists would send the
// reviewer to a page that may not.
func validExternalURL(raw string) error {
	if raw == "" {
		return fmt.Errorf("a link is required for a document we do not generate")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("unreadable link")
	}
	if u.Scheme != "https" {
		return fmt.Errorf("the link must be https")
	}
	if u.Host == "" {
		return fmt.Errorf("the link needs a host")
	}
	return nil
}

// ClampVisibility applies DocKind.MinVisibility. It returns the visibility that will be used,
// whether it differs from what was asked for, and why — the "why" being the part that reaches
// the owner, since a setting that silently declines to take effect is worse than one that is
// refused out loud.
//
// VisPrivate is always allowed: it is stricter than any minimum, and a tenant must be able to
// withdraw any document at any time.
func ClampVisibility(kind platform.DocKind, want platform.Visibility) (platform.Visibility, bool, string) {
	switch want {
	case platform.VisPrivate:
		return platform.VisPrivate, false, ""
	case platform.VisPublic, platform.VisGated:
	default:
		return platform.VisGated, true, fmt.Sprintf("%q is not a visibility; gated it", want)
	}
	if want == platform.VisPublic && kind.MinVisibility() == platform.VisGated {
		return platform.VisGated, true, "this document names your open findings, so it cannot be public — a gap list is a roadmap for whoever reads it. It stays available behind the access request."
	}
	return want, false, ""
}

// DocumentKey identifies a document within a tenant's config. Kind alone is not enough: a
// tenant pursuing SOC 2 and HIPAA offers two compliance reports.
func DocumentKey(d platform.TrustDocument) string {
	if d.Framework != "" {
		return string(d.Kind) + "/" + d.Framework
	}
	return string(d.Kind)
}

// Availability reports which of the configured documents this tenant can actually produce
// right now, keyed by DocumentKey. The caller computes it from real state — a completed scan,
// control records for the framework, a non-empty vendor inventory — because only the caller
// can see that state, and because a document's availability is a fact about the tenant rather
// than about the configuration.
type Availability map[string]bool

// Entry is one row as a particular visitor sees it.
type Entry struct {
	Kind       platform.DocKind    `json:"kind"`
	Title      string              `json:"title"`
	Framework  string              `json:"framework,omitempty"`
	Note       string              `json:"note,omitempty"`
	Visibility platform.Visibility `json:"visibility"`
	// Readable is whether THIS visitor may open it now. A gated row is listed to an ungated
	// visitor with Readable false — that is what tells them there is something worth
	// requesting — but it is never served.
	Readable bool `json:"readable"`
	// Generated distinguishes a document produced from live posture from a link to something
	// the tenant hosts. Shown to the buyer, because "current as of the moment you opened it"
	// and "a file uploaded at some point" are different claims about the same row.
	Generated bool `json:"generated"`
	// URL is populated only for an external document the visitor may actually read. Withheld
	// otherwise, so a locked row cannot be bypassed by reading the listing.
	URL string `json:"url,omitempty"`
}

// Catalog renders the document list for one visitor.
//
// granted says whether this visitor holds a live access grant. avail says which documents
// exist. Anything unavailable is DROPPED rather than shown locked: a locked row is a claim
// that the document exists and is merely being withheld, and on this page that claim is
// exactly what a buyer would act on.
func Catalog(cfg platform.TrustCenterConfig, avail Availability, granted bool) []Entry {
	out := make([]Entry, 0, len(cfg.Documents))
	for _, d := range cfg.Documents {
		if d.Visibility == platform.VisPrivate {
			continue
		}
		if !avail[DocumentKey(d)] {
			continue
		}
		readable := d.Visibility == platform.VisPublic || granted
		e := Entry{
			Kind: d.Kind, Title: DocumentTitle(d), Framework: d.Framework, Note: d.Note,
			Visibility: d.Visibility, Readable: readable, Generated: d.Kind.Generated(),
		}
		if readable && !d.Kind.Generated() {
			e.URL = d.URL
		}
		out = append(out, e)
	}
	return out
}

// Find returns the configured document matching a kind+framework request, and whether it is
// readable by this visitor. Every document fetch goes through it, so the listing and the fetch
// cannot disagree about what is gated — the failure where a row renders locked and the
// underlying endpoint serves it anyway.
func Find(cfg platform.TrustCenterConfig, kind platform.DocKind, framework string, avail Availability, granted bool) (platform.TrustDocument, bool) {
	for _, d := range cfg.Documents {
		if d.Kind != kind || d.Framework != framework {
			continue
		}
		if d.Visibility == platform.VisPrivate || !avail[DocumentKey(d)] {
			return platform.TrustDocument{}, false
		}
		if d.Visibility == platform.VisGated && !granted {
			return platform.TrustDocument{}, false
		}
		return d, true
	}
	return platform.TrustDocument{}, false
}

var defaultTitles = map[platform.DocKind]string{
	platform.DocOverview:         "Security posture overview",
	platform.DocQuestionnaire:    "Security questionnaire",
	platform.DocSubprocessors:    "Sub-processors",
	platform.DocPolicies:         "Security policies",
	platform.DocComplianceReport: "Compliance report",
	platform.DocVAPTReport:       "Penetration test report",
	platform.DocEvidencePack:     "Signed evidence pack",
	platform.DocExternal:         "Document",
}

// DocumentTitle is the tenant's override, else the kind's default, else the raw kind. The last
// fallback exists so a kind added without a title still renders as itself rather than as an
// empty row.
func DocumentTitle(d platform.TrustDocument) string {
	if d.Title != "" {
		return d.Title
	}
	if t, ok := defaultTitles[d.Kind]; ok {
		return t
	}
	return string(d.Kind)
}

// RequiresNDA reports whether this tenant gates on a click-through agreement.
func RequiresNDA(cfg platform.TrustCenterConfig) bool { return strings.TrimSpace(cfg.NDAText) != "" }

// NDAHash digests the exact agreement text a buyer was shown.
//
// Recording the digest rather than a boolean is what makes the acceptance mean something
// afterwards. NDAText is editable configuration: if all we stored were "accepted", a tenant
// who later rewrote the terms would have a record indistinguishable from one where the buyer
// had agreed to the new text. The digest pins WHICH text — the same reason a scan pins its
// corpus version into the evidence rather than recording that a corpus was used.
func NDAHash(text string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(text)))
	return hex.EncodeToString(sum[:])
}

// NewAccessToken mints a buyer's access token and its stored digest. The token is returned
// once, to be put in the approval mail; only the digest is persisted, so a store dump yields
// no working access. Same treatment as the password-reset link.
func NewAccessToken() (token, hash string, err error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", "", err
	}
	token = base64.RawURLEncoding.EncodeToString(buf)
	return token, HashToken(token), nil
}

// HashToken digests a presented token for comparison against the stored hash.
func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// EmailDomain extracts the lower-cased domain of an address, or "" if there isn't one.
func EmailDomain(email string) string {
	at := strings.LastIndex(email, "@")
	if at < 0 || at == len(email)-1 {
		return ""
	}
	return strings.ToLower(strings.TrimSpace(email[at+1:]))
}

// AutoApproves reports whether an auto-approve rule covers this address.
//
// The match is on the exact domain, not a suffix. Suffix matching would make a rule for
// "acme.com" also admit "notacme.com" and "acme.com.attacker.example" — the classic
// domain-suffix bug, here deciding who reads a penetration-test report.
func AutoApproves(cfg platform.TrustCenterConfig, email string) bool {
	d := EmailDomain(email)
	if d == "" {
		return false
	}
	for _, allowed := range cfg.AutoApproveDomains {
		if d == allowed {
			return true
		}
	}
	return false
}

// GrantTTL is the configured access window.
func GrantTTL(cfg platform.TrustCenterConfig) time.Duration {
	if cfg.GrantTTLHours <= 0 {
		return DefaultGrantTTL
	}
	d := time.Duration(cfg.GrantTTLHours) * time.Hour
	if d > MaxGrantTTL {
		return MaxGrantTTL
	}
	return d
}

// Approve marks a request approved and stamps its grant window. decidedBy is the human who
// approved, or "" when a rule did — AutoApproved records which, so the access log can show
// whether anyone actually looked at a given request.
func Approve(cfg platform.TrustCenterConfig, req platform.TrustAccessRequest, decidedBy string, auto bool, now time.Time) platform.TrustAccessRequest {
	req.Status = platform.TrustReqApproved
	req.DecidedAt = now
	req.DecidedBy = strings.TrimSpace(decidedBy)
	req.AutoApproved = auto
	req.Revoked = false
	req.ExpiresAt = now.Add(GrantTTL(cfg))
	return req
}

// Deny records a refusal. The request is KEPT: a buyer who was turned down is a fact about the
// deal, and deleting the row would leave the owner unable to tell it from one that never came.
func Deny(req platform.TrustAccessRequest, decidedBy string, now time.Time) platform.TrustAccessRequest {
	req.Status = platform.TrustReqDenied
	req.DecidedAt = now
	req.DecidedBy = strings.TrimSpace(decidedBy)
	req.TokenHash = ""
	req.ExpiresAt = time.Time{}
	return req
}

// MaxViewLog bounds the per-request access log. A grant read repeatedly should not grow a
// tenant record without limit; the oldest entries are dropped, since the recent ones are what
// anyone acts on.
const MaxViewLog = 500

// RecordView appends to the access log.
func RecordView(req platform.TrustAccessRequest, kind platform.DocKind, framework string, now time.Time) platform.TrustAccessRequest {
	req.Views = append(req.Views, platform.TrustView{At: now, Kind: kind, Framework: framework})
	if len(req.Views) > MaxViewLog {
		req.Views = req.Views[len(req.Views)-MaxViewLog:]
	}
	return req
}

// Watermark is the provenance line stamped onto every generated document a granted buyer
// downloads. It names who it was issued to and when, so a copy that turns up elsewhere can be
// traced to the grant that produced it — the deterrent the category relies on, and the only
// control available for a document whose whole purpose is to be forwarded.
//
// It also carries the generation date, which is the honest half: these documents regenerate
// from live posture, so a copy read six months later describes a state that has moved on.
func Watermark(org, email string, at time.Time) string {
	e := strings.TrimSpace(email)
	if e == "" {
		e = "an approved reviewer"
	}
	return fmt.Sprintf("Provided in confidence to %s via the %s Trust Center. Generated from live security posture on %s; it describes that posture at that moment, not a fixed report.",
		e, org, at.UTC().Format("2 January 2006, 15:04 MST"))
}

// PendingFirst orders requests for the owner's desk: pending ones first (they are the ones
// blocking somebody's evaluation), then most recently requested.
func PendingFirst(reqs []platform.TrustAccessRequest) []platform.TrustAccessRequest {
	out := append([]platform.TrustAccessRequest(nil), reqs...)
	sort.SliceStable(out, func(i, j int) bool {
		pi, pj := out[i].Status == platform.TrustReqPending, out[j].Status == platform.TrustReqPending
		if pi != pj {
			return pi
		}
		return out[i].RequestedAt.After(out[j].RequestedAt)
	})
	return out
}
