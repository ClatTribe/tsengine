package platformapi

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/ClatTribe/tsengine/pkg/platform"
)

// feedback.go is the human half of the verification-policy signal.
//
// Every other feedback channel the product has is INFERRED from an action the customer
// took for some other reason — they suppressed an issue, they reinstated one, a re-scan
// confirmed their fix. Those are cheap and honest, but they all answer the same
// question: did we rank this right. None of them can answer the question a security
// team actually stakes its reputation on — WAS OUR PROOF GOOD ENOUGH — because a person
// who reads a finding, believes it, and thinks the evidence was thin has no way to say
// so without hiding the finding.
//
// So this endpoint is deliberately NOT the ignore endpoint with an extra field. It
// records an opinion and changes nothing: no suppression, no severity change, no effect
// on what the customer sees next. That separation is the point — feedback a person
// suspects will hide their finding is feedback they will not give honestly.

// handleFeedback records a person's judgement about one issue. Latest-wins per issue:
// someone changing their mind replaces their earlier opinion rather than leaving the
// corpus holding both.
func (d Deps) handleFeedback(w http.ResponseWriter, r *http.Request, tenantID string) {
	var body struct {
		Key      string `json:"key"`
		Verdict  string `json:"verdict"`
		Evidence string `json:"evidence"`
		Note     string `json:"note"`
		By       string `json:"by"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body); err != nil ||
		strings.TrimSpace(body.Key) == "" {
		writeJSON(w, http.StatusBadRequest, errBody("a non-empty issue 'key' is required"))
		return
	}
	verdict := strings.ToLower(strings.TrimSpace(body.Verdict))
	evidence := strings.ToLower(strings.TrimSpace(body.Evidence))

	// An unrecognised label is REFUSED rather than stored as free text. A corpus whose
	// labels are open-ended cannot be counted, and a label nobody defined cannot be
	// learned from — so the failure belongs here, loudly, not three months later when
	// someone tries to score it.
	if !platform.ValidFeedbackVerdict(verdict) {
		writeJSON(w, http.StatusBadRequest, errBody(
			"'verdict' must be one of: real, false_positive, unclear"))
		return
	}
	if !platform.ValidFeedbackEvidence(evidence) {
		writeJSON(w, http.StatusBadRequest, errBody(
			"'evidence', when given, must be one of: sufficient, insufficient"))
		return
	}

	fb := platform.Feedback{
		TenantID: tenantID, IssueKey: body.Key, Verdict: verdict, Evidence: evidence,
		Note: body.Note, By: body.By, At: time.Now().UTC(),
	}
	if err := d.Store.PutFeedback(r.Context(), fb); err != nil {
		respond(w, nil, err)
		return
	}
	if d.Recorder != nil {
		d.Recorder.Record("issue feedback", "issue_feedback", map[string]any{
			"tenant_id": tenantID, "issue_key": body.Key,
			"verdict": verdict, "evidence": evidence, "by": body.By,
		}, "human judgement recorded")
	}
	writeJSON(w, http.StatusOK, fb)
}

// handleListFeedback returns this tenant's judgements. Tenant-scoped like every other
// store read (§18.2 inv. 2).
func (d Deps) handleListFeedback(w http.ResponseWriter, r *http.Request, tenantID string) {
	fbs, err := d.Store.ListFeedback(r.Context(), tenantID)
	if err != nil {
		respond(w, nil, err)
		return
	}
	if fbs == nil {
		fbs = []platform.Feedback{} // never null: the frontend maps over this
	}
	writeJSON(w, http.StatusOK, map[string]any{"feedback": fbs, "count": len(fbs)})
}
