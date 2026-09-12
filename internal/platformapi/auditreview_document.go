package platformapi

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/ClatTribe/tsengine/internal/auditreview"
)

// handleAuditCertificateDocument serves the certificate as a DOCUMENT — the print-ready page a
// customer attaches to a hosting request, or the Markdown that travels in a ticket — attested with
// the platform key so a reader holding the JSON can prove it was not altered.
//
// It is the GET twin of handleAuditCertificate (POST, JSON). Same review, same options, same
// Certify: the two cannot disagree about whether a certificate exists. What differs is the refusal
// discipline a document needs and a JSON preview does not:
//
//   - 409 with every blocker when the audit cannot be certified — a document titled "certificate" is
//     never served for an audit that is not one;
//   - 501 when this deployment has no signing key, as the evidence pack does — this endpoint never
//     serves an unsigned artifact a reader would take for a signed one;
//   - every served document is ledger-recorded with its digest, because a signed certificate is a
//     claim someone will rely on and the ledger is where such claims are meant to be checkable.
//
// ?target= names the application; ?format=html (default) | md | json; ?auditor=, ?block_at_or_above=
// and repeated ?not_tested= mirror the POST body.
func (d Deps) handleAuditCertificateDocument(w http.ResponseWriter, r *http.Request, tenantID string) {
	q := r.URL.Query()
	target := strings.TrimSpace(q.Get("target"))
	if target == "" {
		writeJSON(w, http.StatusBadRequest, errBody("a target application is required"))
		return
	}
	auditor := strings.TrimSpace(q.Get("auditor"))
	if auditor == "" {
		auditor = d.actingEmail(r)
	}
	rev, err := d.buildAuditReview(r, tenantID, target)
	if err != nil {
		respond(w, nil, err)
		return
	}
	opt := d.certifyOptions(r, tenantID, target, auditor)
	for _, n := range q["not_tested"] {
		if n = strings.TrimSpace(n); n != "" {
			opt.NotTested = append(opt.NotTested, n)
		}
	}
	if s := strings.TrimSpace(q.Get("block_at_or_above")); s != "" {
		opt.BlockAtOrAbove = s
	}
	now := time.Now().UTC()
	cert, blockers := auditreview.Certify(rev, opt, now)
	if cert == nil {
		writeJSON(w, http.StatusConflict, map[string]any{
			"error": "this audit cannot be certified yet", "blockers": blockers,
		})
		return
	}
	if d.EvidenceSigner == nil {
		writeJSON(w, http.StatusNotImplemented, errBody(
			"certificate signing is not configured on this deployment — set a signing key "+
				"(TSENGINE_SIGNING_KEY path via attest.LoadOrCreate); this endpoint never serves an unsigned certificate"))
		return
	}
	priv, signer, serr := d.EvidenceSigner()
	if serr != nil {
		writeJSON(w, http.StatusInternalServerError, errBody("load signing key: "+serr.Error()))
		return
	}
	if serr := auditreview.Sign(cert, signer, priv, now); serr != nil {
		writeJSON(w, http.StatusInternalServerError, errBody("sign: "+serr.Error()))
		return
	}
	if d.Recorder != nil {
		d.Recorder.Record("audit certificate document served", "audit_review",
			map[string]any{"tenant_id": tenantID, "target": cert.Target, "certificate_id": cert.ID, "auditor": cert.Auditor,
				"firm": cert.Firm, "capacity": cert.Capacity, "sha256": cert.Attestation.SHA256, "format": q.Get("format")},
			"signed Safe-to-Host certificate served as a document")
	}
	switch q.Get("format") {
	case "md":
		w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
		_, _ = io.WriteString(w, auditreview.RenderMarkdown(cert))
	case "json":
		// Byte-faithful, as the evidence pack: writeJSON's nil-slice filling would alter the body
		// after the attestation was computed and every verifier would then report tampering.
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(cert)
	default:
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = io.WriteString(w, auditreview.RenderHTML(cert))
	}
}
