package platformapi

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/ClatTribe/tsengine/pkg/platform"
)

// The human-expert review surface (Track 2 / U2): the "AI + a human" escalation
// SMB security buyers expect (a managed-SOC / vCISO second opinion). A tenant
// requests review on a finding or a proposed action; an expert resolves it with a
// verdict. Request + resolution are tenant-scoped and signed into the ledger
// (§18.2 inv. 4), so the human decision is as auditable as an auto-applied one.

// handleCreateReview opens a review request.
func (d Deps) handleCreateReview(w http.ResponseWriter, r *http.Request, tenantID string) {
	var body struct {
		Subject   string `json:"subject"`
		SubjectID string `json:"subject_id"`
		Note      string `json:"note"`
		Requester string `json:"requester"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, errBody("bad body"))
		return
	}
	// A review can be opened on a finding, a proposed action, or a discovered-posture subject
	// (a risky third-party SaaS app / non-human identity) so the founder can escalate "is this
	// over-permissioned app OK?" to a human expert — the MSP/managed HITL the product provides.
	switch body.Subject {
	case "finding", "action", "saas_app", "identity":
	default:
		writeJSON(w, http.StatusBadRequest, errBody(`subject must be "finding", "action", "saas_app", or "identity"`))
		return
	}
	if body.SubjectID == "" {
		writeJSON(w, http.StatusBadRequest, errBody("subject_id is required"))
		return
	}
	rr := platform.ReviewRequest{
		ID:        d.newID("rev"),
		TenantID:  tenantID,
		Subject:   body.Subject,
		SubjectID: body.SubjectID,
		Note:      body.Note,
		Requester: body.Requester,
		Status:    platform.ReviewOpen,
		CreatedAt: time.Now().UTC(),
	}
	if err := d.Store.PutReviewRequest(r.Context(), rr); err != nil {
		writeJSON(w, http.StatusInternalServerError, errBody(err.Error()))
		return
	}
	d.recordReview("review_requested", rr)
	writeJSON(w, http.StatusCreated, rr)
}

// handleListReviews returns the tenant's review requests (open + resolved).
func (d Deps) handleListReviews(w http.ResponseWriter, r *http.Request, tenantID string) {
	rs, err := d.Store.ListReviewRequests(r.Context(), tenantID)
	respond(w, rs, err)
}

// handleResolveReview records an expert's verdict and closes the request.
func (d Deps) handleResolveReview(w http.ResponseWriter, r *http.Request, tenantID string) {
	id := r.PathValue("id")
	rs, err := d.Store.ListReviewRequests(r.Context(), tenantID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errBody(err.Error()))
		return
	}
	var rr *platform.ReviewRequest
	for i := range rs {
		if rs[i].ID == id {
			rr = &rs[i]
			break
		}
	}
	if rr == nil {
		writeJSON(w, http.StatusNotFound, errBody("review not found"))
		return
	}
	var body struct {
		Resolution string `json:"resolution"`
		Reviewer   string `json:"reviewer"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	rr.Status = platform.ReviewResolved
	rr.Resolution = body.Resolution
	rr.Reviewer = body.Reviewer
	rr.ResolvedAt = time.Now().UTC()
	if err := d.Store.PutReviewRequest(r.Context(), *rr); err != nil {
		writeJSON(w, http.StatusInternalServerError, errBody(err.Error()))
		return
	}
	d.recordReview("review_resolved", *rr)
	writeJSON(w, http.StatusOK, rr)
}

// recordReview signs the request/resolution into the ledger (nil Recorder → no-op,
// graceful — mirrors the detect layer).
func (d Deps) recordReview(action string, rr platform.ReviewRequest) {
	if d.Recorder == nil {
		return
	}
	d.Recorder.Record(action, "review", map[string]any{
		"review_id": rr.ID, "tenant_id": rr.TenantID,
		"subject": rr.Subject, "subject_id": rr.SubjectID, "reviewer": rr.Reviewer,
	}, rr.Status)
}
