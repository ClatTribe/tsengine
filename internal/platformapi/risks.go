package platformapi

import (
	"encoding/json"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/ClatTribe/tsengine/internal/grc"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

// risks.go is the risk-register API — the vCISO judgment artifact. The engine PROPOSES candidate
// risks grounded in real findings (POST /v1/risks/seed); a NAMED HUMAN makes the treatment decision
// (POST /v1/risks/{id}/decision), which is signed into the ledger. The agent never accepts residual
// risk on its own — that's the human-in-the-loop top layer a consultant otherwise owns.

// handleListRisks returns the register (highest-score first) + the board/owner summary.
func (d Deps) handleListRisks(w http.ResponseWriter, r *http.Request, tenantID string) {
	risks, err := d.Store.ListRisks(r.Context(), tenantID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errBody(err.Error()))
		return
	}
	sort.SliceStable(risks, func(i, j int) bool {
		if risks[i].Score() != risks[j].Score() {
			return risks[i].Score() > risks[j].Score()
		}
		return risks[i].ID < risks[j].ID
	})
	if risks == nil {
		risks = []platform.Risk{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"risks": risks, "summary": grc.Summarize(risks)})
}

// handleCreateRisk adds a manual risk-register entry. Title required; likelihood/impact 1–5.
func (d Deps) handleCreateRisk(w http.ResponseWriter, r *http.Request, tenantID string) {
	var body struct {
		Title       string `json:"title"`
		Description string `json:"description"`
		Category    string `json:"category"`
		Likelihood  int    `json:"likelihood"`
		Impact      int    `json:"impact"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, errBody("invalid request"))
		return
	}
	title := strings.TrimSpace(body.Title)
	if title == "" {
		writeJSON(w, http.StatusBadRequest, errBody("title is required"))
		return
	}
	id := "risk-" + tenantID
	if d.NewID != nil {
		id = "risk-" + d.NewID()
	}
	rk := platform.Risk{
		ID:          id,
		TenantID:    tenantID,
		Title:       title,
		Description: strings.TrimSpace(body.Description),
		Category:    strings.TrimSpace(body.Category),
		Likelihood:  body.Likelihood,
		Impact:      body.Impact,
		Status:      platform.RiskOpen,
		CreatedAt:   time.Now().UTC(),
	}
	if err := d.Store.PutRisk(r.Context(), rk); err != nil {
		writeJSON(w, http.StatusInternalServerError, errBody(err.Error()))
		return
	}
	writeJSON(w, http.StatusOK, rk)
}

// handleSeedRisks proposes candidate risks from the tenant's current high+ findings (grounded). It
// upserts a candidate ONLY when no risk with that id has already been decided by a human — a human
// decision is never clobbered by a re-seed.
func (d Deps) handleSeedRisks(w http.ResponseWriter, r *http.Request, tenantID string) {
	findings, err := d.Store.ListFindings(r.Context(), tenantID, store.FindingFilter{})
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errBody(err.Error()))
		return
	}
	existing, err := d.Store.ListRisks(r.Context(), tenantID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errBody(err.Error()))
		return
	}
	decided := map[string]bool{}
	for _, e := range existing {
		if e.DecidedBy != "" || !e.Proposed { // a human touched it (decided, or converted from proposed)
			decided[e.ID] = true
		}
	}
	candidates := grc.CandidateRisks(tenantID, findings, time.Now().UTC())
	seeded := make([]platform.Risk, 0, len(candidates))
	for _, c := range candidates {
		if decided[c.ID] {
			continue // never overwrite a human's decision
		}
		if err := d.Store.PutRisk(r.Context(), c); err != nil {
			writeJSON(w, http.StatusInternalServerError, errBody(err.Error()))
			return
		}
		seeded = append(seeded, c)
	}
	writeJSON(w, http.StatusOK, map[string]any{"seeded": seeded, "count": len(seeded)})
}

// handleDecideRisk is the HUMAN-IN-THE-LOOP treatment decision. A named owner accepts/mitigates/
// transfers/avoids the risk with a rationale; the decision is signed into the ledger. The agent
// cannot reach this path — only a person POSTs a decision.
func (d Deps) handleDecideRisk(w http.ResponseWriter, r *http.Request, tenantID string) {
	id := r.PathValue("id")
	var body struct {
		Treatment  string `json:"treatment"`
		Owner      string `json:"owner"`
		Rationale  string `json:"rationale"`
		Likelihood int    `json:"likelihood"` // optional override of the proposed L
		Impact     int    `json:"impact"`     // optional override of the proposed I
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, errBody("invalid request"))
		return
	}
	treatment := strings.ToLower(strings.TrimSpace(body.Treatment))
	owner := strings.TrimSpace(body.Owner)
	if !validTreatment(treatment) {
		writeJSON(w, http.StatusBadRequest, errBody("treatment must be one of: accept, mitigate, transfer, avoid"))
		return
	}
	if owner == "" {
		writeJSON(w, http.StatusBadRequest, errBody("a named owner is required to decide a risk"))
		return
	}

	risks, err := d.Store.ListRisks(r.Context(), tenantID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errBody(err.Error()))
		return
	}
	var rk platform.Risk
	found := false
	for _, x := range risks {
		if x.ID == id {
			rk = x
			found = true
			break
		}
	}
	if !found {
		writeJSON(w, http.StatusNotFound, errBody("risk not found"))
		return
	}

	rk.Treatment = treatment
	rk.Owner = owner
	rk.Rationale = strings.TrimSpace(body.Rationale)
	rk.Proposed = false // a human owns it now
	rk.DecidedBy = owner
	rk.DecidedAt = time.Now().UTC()
	rk.Capacity, rk.Firm = d.practitionerCapacity(r, tenantID, owner) // who the decider works for
	if body.Likelihood != 0 {
		rk.Likelihood = body.Likelihood
	}
	if body.Impact != 0 {
		rk.Impact = body.Impact
	}
	rk.Status = statusForTreatment(treatment)
	if d.Recorder != nil {
		d.Recorder.Record("risk treatment decided (human)", "risk_decision",
			map[string]any{"tenant_id": tenantID, "risk_id": rk.ID, "treatment": treatment, "owner": owner, "score": rk.Score()},
			"residual risk "+treatment+" by "+owner)
		rk.LedgerRef = "risk-decision-" + rk.ID
	}
	if err := d.Store.PutRisk(r.Context(), rk); err != nil {
		writeJSON(w, http.StatusInternalServerError, errBody(err.Error()))
		return
	}
	writeJSON(w, http.StatusOK, rk)
}

func validTreatment(t string) bool {
	switch t {
	case platform.RiskTreatmentAccept, platform.RiskTreatmentMitigate,
		platform.RiskTreatmentTransfer, platform.RiskTreatmentAvoid:
		return true
	}
	return false
}

// statusForTreatment maps a treatment to the resulting risk status: accept → accepted (residual
// risk owned), everything else → treating (work in progress).
func statusForTreatment(t string) string {
	if t == platform.RiskTreatmentAccept {
		return platform.RiskAccepted
	}
	return platform.RiskTreating
}
