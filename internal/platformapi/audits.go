package platformapi

import (
	"encoding/json"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/ClatTribe/tsengine/internal/grc"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

// audits.go is the audit-engagement API — the legal "audit-ready, not the audit" layer. The product
// assembles the controls to be attested (from the tenant's real posture) and tracks the engagement;
// the per-control verdict is an INDEPENDENT human auditor's (POST /v1/audits/{id}/attest), recorded
// with the auditor's name + signed into the ledger. The engine never attests a control.

type auditView struct {
	platform.AuditEngagement
	Summary grc.AuditSummary `json:"summary"`
}

func (d Deps) handleListAudits(w http.ResponseWriter, r *http.Request, tenantID string) {
	es, err := d.Store.ListAuditEngagements(r.Context(), tenantID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errBody(err.Error()))
		return
	}
	sort.SliceStable(es, func(i, j int) bool { return es[i].CreatedAt.After(es[j].CreatedAt) })
	out := make([]auditView, 0, len(es))
	for _, e := range es {
		out = append(out, auditView{AuditEngagement: e, Summary: grc.SummarizeAudit(e)})
	}
	writeJSON(w, http.StatusOK, map[string]any{"audits": out})
}

// handleCreateAudit opens an engagement and seeds the controls to attest from the tenant's posture
// for the framework (grounded — only controls the tenant actually has).
func (d Deps) handleCreateAudit(w http.ResponseWriter, r *http.Request, tenantID string) {
	var body struct {
		Framework    string `json:"framework"`
		AuditType    string `json:"audit_type"`
		AuditorName  string `json:"auditor_name"`
		AuditorFirm  string `json:"auditor_firm"`
		AuditorEmail string `json:"auditor_email"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, errBody("invalid request"))
		return
	}
	framework := strings.TrimSpace(body.Framework)
	if framework == "" {
		writeJSON(w, http.StatusBadRequest, errBody("framework is required"))
		return
	}
	auditType := strings.TrimSpace(body.AuditType)
	if auditType != platform.AuditTypeI && auditType != platform.AuditTypeII {
		auditType = platform.AuditTypeI
	}

	// Seed the controls to attest from the tenant's real posture for this framework.
	var controlIDs []string
	if post, err := d.Store.Posture(r.Context(), tenantID, framework); err == nil {
		for _, c := range post {
			controlIDs = append(controlIDs, c.ControlID)
		}
	}

	id := "audit-" + tenantID
	if d.NewID != nil {
		id = "audit-" + d.NewID()
	}
	e := platform.AuditEngagement{
		ID:           id,
		TenantID:     tenantID,
		Framework:    framework,
		AuditType:    auditType,
		AuditorName:  strings.TrimSpace(body.AuditorName),
		AuditorFirm:  strings.TrimSpace(body.AuditorFirm),
		AuditorEmail: strings.TrimSpace(body.AuditorEmail),
		Status:       platform.AuditPlanning,
		Attestations: grc.SeedAttestations(framework, controlIDs),
		CreatedAt:    time.Now().UTC(),
	}
	if err := d.Store.PutAuditEngagement(r.Context(), e); err != nil {
		writeJSON(w, http.StatusInternalServerError, errBody(err.Error()))
		return
	}
	writeJSON(w, http.StatusOK, auditView{AuditEngagement: e, Summary: grc.SummarizeAudit(e)})
}

// handleAttestControl is the HUMAN-IN-THE-LOOP auditor verdict. A named auditor records passed/
// exception on one control with a note; it's signed into the ledger. The engine cannot reach this.
func (d Deps) handleAttestControl(w http.ResponseWriter, r *http.Request, tenantID string) {
	id := r.PathValue("id")
	var body struct {
		ControlID  string `json:"control_id"`
		Verdict    string `json:"verdict"`
		Note       string `json:"note"`
		AttestedBy string `json:"attested_by"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, errBody("invalid request"))
		return
	}
	verdict := strings.ToLower(strings.TrimSpace(body.Verdict))
	if verdict != platform.AttestPassed && verdict != platform.AttestException {
		writeJSON(w, http.StatusBadRequest, errBody("verdict must be one of: passed, exception"))
		return
	}
	attestedBy := strings.TrimSpace(body.AttestedBy)
	if attestedBy == "" {
		writeJSON(w, http.StatusBadRequest, errBody("attested_by (the auditor's name) is required"))
		return
	}
	controlID := strings.TrimSpace(body.ControlID)

	e, ok := d.findAudit(r, tenantID, id)
	if !ok {
		writeJSON(w, http.StatusNotFound, errBody("audit engagement not found"))
		return
	}
	found := false
	for i := range e.Attestations {
		if e.Attestations[i].ControlID == controlID {
			e.Attestations[i].Verdict = verdict
			e.Attestations[i].Note = strings.TrimSpace(body.Note)
			e.Attestations[i].AttestedBy = attestedBy
			e.Attestations[i].AttestedAt = time.Now().UTC()
			found = true
			break
		}
	}
	if !found {
		writeJSON(w, http.StatusNotFound, errBody("control not in this engagement"))
		return
	}
	if e.Status == platform.AuditPlanning {
		e.Status = platform.AuditFieldwork // first attestation moves it into fieldwork
	}
	if d.Recorder != nil {
		d.Recorder.Record("control attested (external auditor)", "audit_attest",
			map[string]any{"tenant_id": tenantID, "audit_id": e.ID, "control_id": controlID, "verdict": verdict, "auditor": attestedBy},
			"control "+controlID+" "+verdict+" by "+attestedBy)
	}
	if err := d.Store.PutAuditEngagement(r.Context(), e); err != nil {
		writeJSON(w, http.StatusInternalServerError, errBody(err.Error()))
		return
	}
	writeJSON(w, http.StatusOK, auditView{AuditEngagement: e, Summary: grc.SummarizeAudit(e)})
}

// handleIssueAudit marks the engagement issued — the auditor has rendered their report. Requires the
// engagement to name the auditor (the legal signer) and every control to be attested.
func (d Deps) handleIssueAudit(w http.ResponseWriter, r *http.Request, tenantID string) {
	id := r.PathValue("id")
	e, ok := d.findAudit(r, tenantID, id)
	if !ok {
		writeJSON(w, http.StatusNotFound, errBody("audit engagement not found"))
		return
	}
	if e.AuditorName == "" {
		writeJSON(w, http.StatusBadRequest, errBody("an audit can only be issued by a named auditor"))
		return
	}
	if s := grc.SummarizeAudit(e); s.Pending > 0 {
		writeJSON(w, http.StatusBadRequest, errBody("every control must be attested before the engagement can be issued"))
		return
	}
	e.Status = platform.AuditIssued
	e.IssuedAt = time.Now().UTC()
	if d.Recorder != nil {
		d.Recorder.Record("audit engagement issued", "audit_issue",
			map[string]any{"tenant_id": tenantID, "audit_id": e.ID, "framework": e.Framework, "auditor": e.AuditorName}, "audit issued by "+e.AuditorName)
		e.LedgerRef = "audit-issued-" + e.ID
	}
	if err := d.Store.PutAuditEngagement(r.Context(), e); err != nil {
		writeJSON(w, http.StatusInternalServerError, errBody(err.Error()))
		return
	}
	writeJSON(w, http.StatusOK, auditView{AuditEngagement: e, Summary: grc.SummarizeAudit(e)})
}

func (d Deps) findAudit(r *http.Request, tenantID, id string) (platform.AuditEngagement, bool) {
	es, err := d.Store.ListAuditEngagements(r.Context(), tenantID)
	if err != nil {
		return platform.AuditEngagement{}, false
	}
	for _, e := range es {
		if e.ID == id {
			return e, true
		}
	}
	return platform.AuditEngagement{}, false
}
