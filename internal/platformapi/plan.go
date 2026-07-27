package platformapi

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/ClatTribe/tsengine/pkg/platform"
)

// planLimits resolves a tenant's plan entitlements, defaulting to Free on any lookup error
// (fail-safe: an unreadable plan never grants paid entitlements or the operator's LLM budget).
func (d Deps) planLimits(ctx context.Context, tenantID string) platform.PlanLimits {
	t, err := d.Store.GetTenant(ctx, tenantID)
	if err != nil {
		return platform.Entitlements(platform.PlanFree)
	}
	return platform.Entitlements(t.Plan)
}

// upgradeContactPath is where a plan-blocked customer is sent. Kept in one place so the API
// and the UI cannot drift.
const upgradeContactPath = "/demo"

// entitlementBlocked writes the canonical 402 for a plan limit. A bare error string saying
// "upgrade" was a dead end — there is no checkout to send anyone to — so the response carries
// a machine-readable reason and a real destination, and states plainly that fulfilment is
// contact-sales rather than implying a self-serve payment page that does not exist.
func entitlementBlocked(w http.ResponseWriter, reason, detail string) {
	writeJSON(w, http.StatusPaymentRequired, map[string]any{
		"error":        detail,
		"reason":       reason,
		"upgrade_url":  upgradeContactPath,
		"upgrade_kind": "contact_sales",
	})
}

// handleSetTenantPlan (POST /v1/tenants/{id}/plan) changes an EXISTING tenant's plan.
//
// This closes a hole that made the pricing page unfulfillable: a plan could only ever be set at
// tenant CREATION, so a customer who signed up free could not be moved to a paid plan by any
// supported path. Gated by the platform token (operator-only, like provisioning) — a tenant
// session must never upgrade itself, or the economic gate would be self-serve bypassable.
func (d Deps) handleSetTenantPlan(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var body struct {
		Plan string `json:"plan"`
		Note string `json:"note,omitempty"` // order / invoice reference, for the audit trail
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body); err != nil || body.Plan == "" {
		writeJSON(w, http.StatusBadRequest, errBody(`a plan is required, e.g. {"plan":"growth"}`))
		return
	}
	// ValidatePlan, not NormalizePlan: normalizing is fail-safe-to-Free, which on a WRITE would
	// silently downgrade a customer who just paid because of a typo.
	canonical, verr := platform.ValidatePlan(body.Plan)
	if verr != nil {
		writeJSON(w, http.StatusBadRequest, errBody(verr.Error()))
		return
	}

	t, err := d.Store.GetTenant(r.Context(), id)
	if err != nil {
		respond(w, nil, err)
		return
	}
	before := t.Plan
	t.Plan = canonical
	if err := d.Store.PutTenant(r.Context(), t); err != nil {
		writeJSON(w, http.StatusInternalServerError, errBody(err.Error()))
		return
	}
	// A plan change is a commercial fact — it changes what the agent may spend and do — so it
	// belongs in the signed ledger next to every other consequential decision.
	if d.Recorder != nil {
		d.Recorder.Record("tenant plan changed", "billing", map[string]any{
			"tenant_id": id, "from": before, "to": canonical, "note": body.Note,
			"at": time.Now().UTC().Format(time.RFC3339),
		}, "operator plan change")
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"tenant_id": id, "plan": canonical, "previous_plan": before,
		"entitlements": platform.Entitlements(canonical),
	})
}
