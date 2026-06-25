package platformapi

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/ClatTribe/tsengine/pkg/platform"
)

// operator_act.go is the ACT-ON-BEHALF half of the cross-tenant operator console. The queue
// (operator.go) lets the expert SEE every client's pending judgment calls; this lets them MAKE the
// call without context-switching into each client workspace — the point of a single desk for a book
// of clients.
//
// Isolation is preserved by the SAME rule as the queue: the operator may act on a tenant ONLY when
// that tenant's roster names them a practitioner of record (matchPractitioner). An operator who is not
// on the roster gets 403 and the tenant is never mutated — so §18.2 inv. 2 (tenant isolation) holds,
// and the act is still a NAMED human decision (the operator is the named owner), with their
// capacity/firm taken from the roster record (grounded, §10) and signed into the ledger.

// handleOperatorDecideRisk makes a risk treatment decision on behalf of an assigned client tenant.
// POST /v1/operator/tenants/{tenant}/risks/{id}/decision (operator-session gated).
func (d Deps) handleOperatorDecideRisk(w http.ResponseWriter, r *http.Request, op platform.Operator) {
	tenantID := r.PathValue("tenant")
	id := r.PathValue("id")

	t, err := d.Store.GetTenant(r.Context(), tenantID)
	if err != nil {
		writeJSON(w, http.StatusNotFound, errBody("client not found"))
		return
	}
	p, ok := matchPractitioner(t, strings.ToLower(strings.TrimSpace(op.Email)))
	if !ok {
		// the operator is not assigned to this client — never read or mutate it
		writeJSON(w, http.StatusForbidden, errBody("you are not a practitioner of record for this client"))
		return
	}

	var body struct {
		Treatment  string `json:"treatment"`
		Rationale  string `json:"rationale"`
		Likelihood int    `json:"likelihood"`
		Impact     int    `json:"impact"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, errBody("invalid request"))
		return
	}

	owner := strings.TrimSpace(op.Name)
	if owner == "" {
		owner = op.Email // the operator is always a named human; fall back to their email
	}
	// capacity/firm come from the operator's ROSTER record on this tenant (msp | managed), not a typed
	// string — so the act is honestly attributed to who employs them.
	rk, status, err := d.applyRiskDecision(r, tenantID, id, body.Treatment, owner, body.Rationale, p.Capacity, p.Firm, body.Likelihood, body.Impact)
	if err != nil {
		writeJSON(w, status, errBody(err.Error()))
		return
	}
	writeJSON(w, status, rk)
}

// handleOperatorPublishPolicy publishes a draft security policy on behalf of an assigned client, from
// the cross-tenant console. POST /v1/operator/tenants/{tenant}/policies/{id}/publish. Same isolation
// rule as the queue (roster match → else 403); the operator is the named publisher, capacity/firm from
// their roster record, ledger-signed. Together with the risk path this covers the vCISO half of the
// desk (the "vciso" scope alias = risk + policy).
func (d Deps) handleOperatorPublishPolicy(w http.ResponseWriter, r *http.Request, op platform.Operator) {
	tenantID := r.PathValue("tenant")
	id := r.PathValue("id")

	t, err := d.Store.GetTenant(r.Context(), tenantID)
	if err != nil {
		writeJSON(w, http.StatusNotFound, errBody("client not found"))
		return
	}
	pr, ok := matchPractitioner(t, strings.ToLower(strings.TrimSpace(op.Email)))
	if !ok {
		writeJSON(w, http.StatusForbidden, errBody("you are not a practitioner of record for this client"))
		return
	}
	owner := strings.TrimSpace(op.Name)
	if owner == "" {
		owner = op.Email
	}
	p, status, err := d.applyPolicyPublish(r, tenantID, id, owner, pr.Capacity, pr.Firm)
	if err != nil {
		writeJSON(w, status, errBody(err.Error()))
		return
	}
	writeJSON(w, status, p)
}

// handleOperatorSignoffPentest signs off a client's pentest report on behalf — the "named
// accountability on a pentest" HITL act, from the cross-tenant console.
// POST /v1/operator/tenants/{tenant}/pentests/{id}/signoff. Same roster-match gate (403 if not a
// practitioner of record); the operator is the named signer, capacity/firm from their roster record,
// ledger-signed + stamped onto the rendered report.
func (d Deps) handleOperatorSignoffPentest(w http.ResponseWriter, r *http.Request, op platform.Operator) {
	tenantID := r.PathValue("tenant")
	id := r.PathValue("id")

	t, err := d.Store.GetTenant(r.Context(), tenantID)
	if err != nil {
		writeJSON(w, http.StatusNotFound, errBody("client not found"))
		return
	}
	pr, ok := matchPractitioner(t, strings.ToLower(strings.TrimSpace(op.Email)))
	if !ok {
		writeJSON(w, http.StatusForbidden, errBody("you are not a practitioner of record for this client"))
		return
	}
	var body struct {
		Role      string `json:"role"`
		Statement string `json:"statement"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, errBody("invalid request"))
		return
	}
	signer := strings.TrimSpace(op.Name)
	if signer == "" {
		signer = op.Email
	}
	role := strings.TrimSpace(body.Role)
	if role == "" && pr.Credential != "" {
		role = pr.Credential // default the signer's role to their recorded credential (e.g. OSCP)
	}
	eng, status, err := d.applyPentestSignoff(r, tenantID, id, signer, role, body.Statement, pr.Capacity, pr.Firm)
	if err != nil {
		writeJSON(w, status, errBody(err.Error()))
		return
	}
	writeJSON(w, status, eng)
}
