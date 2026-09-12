package platformapi

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/ClatTribe/tsengine/internal/auditreview"
	"github.com/ClatTribe/tsengine/internal/crossdetect"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// auditreview_api.go is the door to the per-application audit review — the workflow an empanelled
// firm runs between "the engine scanned it" and "somebody signs the certificate".
//
// The review is REBUILT from current findings on every read with stored decisions merged back on
// (the internal/recertify shape), because the audit flow these buyers run is draft report →
// remediate → re-test → final report → certificate. Findings move between those steps, and a frozen
// review would send a reviewer to sign off an application whose latest scan found something nobody
// has looked at.

type auditReviewResponse struct {
	auditreview.Review
	// Blockers is why a certificate cannot be issued YET, returned on the read as well as the
	// attempt: a reviewer should see what stands in the way while they work, not discover it when
	// they press the button.
	Blockers []auditreview.Blocker `json:"blockers,omitempty"`
}

// handleAuditReview returns one application's review.
func (d Deps) handleAuditReview(w http.ResponseWriter, r *http.Request, tenantID string) {
	target := strings.TrimSpace(r.URL.Query().Get("target"))
	if target == "" {
		writeJSON(w, http.StatusBadRequest, errBody("a target application is required"))
		return
	}
	rev, err := d.buildAuditReview(r, tenantID, target)
	if err != nil {
		respond(w, nil, err)
		return
	}
	// Blockers computed with the SAME options the issue path uses, so the desk cannot show a
	// reviewer one set of obstacles and then refuse for a different reason.
	_, blockers := auditreview.Certify(rev, d.certifyOptions(r, tenantID, target, ""), time.Now())
	writeJSON(w, http.StatusOK, auditReviewResponse{Review: rev, Blockers: blockers})
}

// handleAuditDisposition records one reviewer's decision about one finding.
func (d Deps) handleAuditDisposition(w http.ResponseWriter, r *http.Request, tenantID string) {
	var body struct {
		Target   string `json:"target"`
		Key      string `json:"key"`
		Verdict  string `json:"verdict"`
		Severity string `json:"severity"`
		Reason   string `json:"reason"`
		By       string `json:"by"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&body); err != nil && err != io.EOF {
		writeJSON(w, http.StatusBadRequest, errBody("invalid request"))
		return
	}
	by := strings.TrimSpace(body.By)
	if by == "" {
		by = d.actingEmail(r) // the signed-in reviewer, never an anonymous default
	}

	disp, err := auditreview.Decide(tenantID, body.Target, body.Key,
		platform.AuditVerdict(strings.TrimSpace(body.Verdict)), body.Severity, body.Reason, by, time.Now())
	if err != nil {
		// The package's refusals are the product, so they reach the caller as themselves rather than
		// as a generic 400: each one names what is missing from a decision that will end up in a
		// signed document.
		writeJSON(w, http.StatusBadRequest, errBody(err.Error()))
		return
	}

	// The engine's severity is needed to know whether a reclassification LOWERED it — the direction
	// that makes a report look better. Taken from the finding rather than the caller.
	rev, err := d.buildAuditReview(r, tenantID, body.Target)
	if err != nil {
		respond(w, nil, err)
		return
	}
	var known bool
	for _, it := range rev.Items {
		if it.Key == body.Key {
			disp = auditreview.MarkDirection(disp, it.Severity)
			known = true
			break
		}
	}
	if !known {
		// A decision about a finding not in scope would sit in the store forever, invisible and
		// uncounted — the off-roster shape. Refused rather than stored.
		writeJSON(w, http.StatusNotFound, errBody("that finding is not in this application's review"))
		return
	}

	if err := d.Store.PutAuditDisposition(r.Context(), disp); err != nil {
		respond(w, nil, err)
		return
	}
	if d.Recorder != nil {
		d.Recorder.Record("audit finding "+string(disp.Verdict), "audit_review",
			map[string]any{"tenant_id": tenantID, "target": disp.Target, "key": disp.Key,
				"verdict": string(disp.Verdict), "severity": disp.Severity, "lowered": disp.Lowered,
				"reason": disp.Reason, "by": disp.By},
			"per-finding disposition for a signed audit report")
	}
	d.handleAuditReviewFor(w, r, tenantID, disp.Target)
}

// handleAuditCertificate issues the certificate, or returns every reason it cannot.
func (d Deps) handleAuditCertificate(w http.ResponseWriter, r *http.Request, tenantID string) {
	var body struct {
		Target         string   `json:"target"`
		Standard       string   `json:"standard"`
		Auditor        string   `json:"auditor"`
		BlockAtOrAbove string   `json:"block_at_or_above"`
		NotTested      []string `json:"not_tested"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&body); err != nil && err != io.EOF {
		writeJSON(w, http.StatusBadRequest, errBody("invalid request"))
		return
	}
	auditor := strings.TrimSpace(body.Auditor)
	if auditor == "" {
		auditor = d.actingEmail(r)
	}
	rev, err := d.buildAuditReview(r, tenantID, body.Target)
	if err != nil {
		respond(w, nil, err)
		return
	}

	opt := d.certifyOptions(r, tenantID, body.Target, auditor)
	opt.Standard = strings.TrimSpace(body.Standard)
	if len(body.NotTested) > 0 {
		opt.NotTested = append(opt.NotTested, body.NotTested...)
	}
	if s := strings.TrimSpace(body.BlockAtOrAbove); s != "" {
		opt.BlockAtOrAbove = s
	}

	cert, blockers := auditreview.Certify(rev, opt, time.Now())
	if cert == nil {
		// 409, not 400: nothing about the REQUEST is malformed — the audit is simply not in a state
		// that can be certified, and the blockers say which.
		writeJSON(w, http.StatusConflict, map[string]any{
			"error": "this audit cannot be certified yet", "blockers": blockers,
		})
		return
	}
	if d.Recorder != nil {
		d.Recorder.Record("audit certificate issued", "audit_review",
			map[string]any{"tenant_id": tenantID, "target": cert.Target, "auditor": cert.Auditor,
				"firm": cert.Firm, "capacity": cert.Capacity, "standard": cert.Standard,
				"findings_reviewed": cert.FindingsReviewed, "excluded": cert.Excluded},
			"Safe-to-Host / web application security audit certificate")
	}
	// The per-application order for this target, if any, advances to certified — nothing is due yet.
	d.markAuditOrdersCertified(r.Context(), tenantID, cert.Target, cert.ID, cert.IssuedAt)
	writeJSON(w, http.StatusOK, cert)
}

func (d Deps) handleAuditReviewFor(w http.ResponseWriter, r *http.Request, tenantID, target string) {
	rev, err := d.buildAuditReview(r, tenantID, target)
	if err != nil {
		respond(w, nil, err)
		return
	}
	_, blockers := auditreview.Certify(rev, d.certifyOptions(r, tenantID, target, ""), time.Now())
	writeJSON(w, http.StatusOK, auditReviewResponse{Review: rev, Blockers: blockers})
}

// buildAuditReview assembles the review from the findings attributed to this application.
//
// Attribution is the LITERAL target match the rest of the platform uses (per-asset compliance, data
// tier, coverage): a finding belongs to this audit only when the application's target really appears
// in its endpoint. Guessing wider would put another application's findings into this certificate.
func (d Deps) buildAuditReview(r *http.Request, tenantID, target string) (auditreview.Review, error) {
	target = strings.TrimSpace(target)
	all, err := d.Store.ListFindings(r.Context(), tenantID, store.FindingFilter{})
	if err != nil {
		return auditreview.Review{}, err
	}
	var scoped []types.Finding
	for _, f := range all {
		if target != "" && strings.Contains(f.Endpoint, target) {
			scoped = append(scoped, f)
		}
	}
	disps, err := d.Store.ListAuditDispositions(r.Context(), tenantID)
	if err != nil {
		return auditreview.Review{}, err
	}
	return auditreview.Build(target, auditStandard, scoped, crossdetect.DedupKey, disps), nil
}

// auditStandard is what these audits are performed against. Named once: the tenders specify
// "Application Security Audit (OWASP Top 10)", and a certificate that cites a standard must cite the
// same one the review was conducted under.
const auditStandard = "OWASP Top 10 (2021)"

// certifyOptions assembles the firm's bar plus the facts the package must not guess.
//
// The auditor's CAPACITY and FIRM are resolved from the practitioner roster, never taken from the
// request — the same rule every other HITL artifact follows, so a certificate cannot claim an
// independent firm signed it because somebody typed one in.
func (d Deps) certifyOptions(r *http.Request, tenantID, target, auditor string) auditreview.CertifyOptions {
	opt := auditreview.CertifyOptions{Standard: auditStandard, Auditor: auditor}
	if auditor != "" {
		opt.Capacity, opt.Firm = d.practitionerCapacity(r, tenantID, auditor)
	}
	opt.NotTested = d.auditNotTested(r, tenantID, target)
	opt.Resolved = d.auditResolved(r, tenantID, target)
	// Scope coverage from the SAME helpers the VAPT report uses, so the certificate can never be
	// issued for a target the report refuses to rate: no completed scan behind it, or a scan that
	// lost a tool. A finding list says nothing about either.
	opt.Untested = d.untestedScope(r.Context(), tenantID, []string{target})
	opt.PartiallyAssessed = d.partiallyAssessedScope(r.Context(), tenantID, []string{target})
	opt.Brand = d.tenantBrand(r, tenantID)
	return opt
}

// auditNotTested is the coverage this audit did NOT cover, read from the scan's own declared gaps
// rather than composed here. A certificate listing only what was checked reads as though everything
// was — and this one goes to a government buyer.
func (d Deps) auditNotTested(r *http.Request, tenantID, target string) []string {
	fs, err := d.Store.ListFindings(r.Context(), tenantID, store.FindingFilter{})
	if err != nil {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, f := range fs {
		if !strings.HasPrefix(f.RuleID, coverageRulePrefix) {
			continue
		}
		if target != "" && !strings.Contains(f.Endpoint, target) {
			continue
		}
		if t := strings.TrimSpace(f.Title); t != "" && !seen[t] {
			seen[t] = true
			out = append(out, t)
		}
	}
	return out
}

// auditResolved marks the findings a re-test PROVED closed — the re-test step every one of these
// tenders bundles into the fee. Grounded: only a verification that actually concluded "fixed"
// counts, so a finding nobody re-tested still blocks the certificate.
func (d Deps) auditResolved(r *http.Request, tenantID, target string) map[string]bool {
	acts, err := d.Store.ListActions(r.Context(), tenantID)
	if err != nil {
		return nil
	}
	out := map[string]bool{}
	for _, a := range acts {
		if a.Verification == nil || a.Verification.Status != platform.FixStatusFixed {
			continue
		}
		for _, k := range a.FindingKeys {
			out[k] = true
		}
	}
	return out
}

// coverageRulePrefix mirrors asset.CoverageRulePrefix. Declared here rather than imported because
// platformapi does not otherwise depend on the asset layer; a test pins the two together.
const coverageRulePrefix = "coverage::"
