package platformapi

import (
	"context"
	"encoding/json"
	"errors"
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
	seeded, err := d.seedRisks(r.Context(), tenantID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errBody(err.Error()))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"seeded": seeded, "count": len(seeded)})
}

// seedRisks clusters the tenant's high+ findings into candidate Risks for the named vCISO to judge,
// persisting only NEW candidates (a human's decision is never clobbered). Idempotent. Shared by the
// on-demand POST /v1/risks/seed AND the L2-agent investigations (cloud-investigate) — so when an agent
// proves an attack path, a candidate risk lands on the vCISO desk automatically (agent proposes → named
// human disposes, §18.4). Grounded: a risk exists only because real findings cite it (§10).
func (d Deps) seedRisks(ctx context.Context, tenantID string) ([]platform.Risk, error) {
	findings, err := d.Store.ListFindings(ctx, tenantID, store.FindingFilter{})
	if err != nil {
		return nil, err
	}
	existing, err := d.Store.ListRisks(ctx, tenantID)
	if err != nil {
		return nil, err
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
		if err := d.Store.PutRisk(ctx, c); err != nil {
			return nil, err
		}
		seeded = append(seeded, c)
	}
	return seeded, nil
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
	// the tenant path resolves the decider's capacity from the roster by their typed name
	cap, firm := d.practitionerCapacity(r, tenantID, strings.TrimSpace(body.Owner))
	rk, status, err := d.applyRiskDecision(r, tenantID, id, body.Treatment, body.Owner, body.Rationale, cap, firm, body.Likelihood, body.Impact)
	if err != nil {
		writeJSON(w, status, errBody(err.Error()))
		return
	}
	writeJSON(w, status, rk)
}

// applyRiskDecision applies a HUMAN treatment decision to a risk and signs it into the ledger. Shared
// by the tenant-session path (handleDecideRisk) and the operator act-on-behalf path
// (handleOperatorDecideRisk) — the only difference between the two is how capacity/firm are resolved
// (typed owner name vs. the operator's roster record), so the gate, validation, and ledger are
// identical. Returns the decided risk, or an HTTP status + error for the caller to render.
func (d Deps) applyRiskDecision(r *http.Request, tenantID, id, treatment, owner, rationale, capacity, firm string, lOver, iOver int) (platform.Risk, int, error) {
	treatment = strings.ToLower(strings.TrimSpace(treatment))
	owner = strings.TrimSpace(owner)
	if !validTreatment(treatment) {
		return platform.Risk{}, http.StatusBadRequest, errors.New("treatment must be one of: accept, mitigate, transfer, avoid")
	}
	if owner == "" {
		return platform.Risk{}, http.StatusBadRequest, errors.New("a named owner is required to decide a risk")
	}
	risks, err := d.Store.ListRisks(r.Context(), tenantID)
	if err != nil {
		return platform.Risk{}, http.StatusInternalServerError, err
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
		return platform.Risk{}, http.StatusNotFound, errors.New("risk not found")
	}
	rk.Treatment = treatment
	rk.Owner = owner
	rk.Rationale = strings.TrimSpace(rationale)
	rk.Proposed = false // a human owns it now
	rk.DecidedBy = owner
	rk.DecidedAt = time.Now().UTC()
	rk.Capacity, rk.Firm = capacity, firm // who the decider works for
	if lOver != 0 {
		rk.Likelihood = lOver
	}
	if iOver != 0 {
		rk.Impact = iOver
	}
	rk.Status = statusForTreatment(treatment)
	if d.Recorder != nil {
		d.Recorder.Record("risk treatment decided (human)", "risk_decision",
			map[string]any{"tenant_id": tenantID, "risk_id": rk.ID, "treatment": treatment, "owner": owner, "capacity": rk.Capacity, "score": rk.Score()},
			"residual risk "+treatment+" by "+owner)
		rk.LedgerRef = "risk-decision-" + rk.ID
	}
	if err := d.Store.PutRisk(r.Context(), rk); err != nil {
		return platform.Risk{}, http.StatusInternalServerError, err
	}
	return rk, http.StatusOK, nil
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
