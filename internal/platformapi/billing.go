package platformapi

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/ClatTribe/tsengine/internal/billing"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

// billing.go is the self-serve purchase path — the difference between a pricing page and a business.
//
// Two endpoints:
//   - POST /v1/billing/checkout — tenant-authed. Creates a real Razorpay order for a catalogued
//     plan+cycle and hands the browser what it needs to open Checkout.
//   - POST /v1/billing/webhook — NOT bearer-authed (Razorpay has no session). Its ONLY defence is the
//     signature, exactly like /v1/slack/interactive. It is what actually flips Tenant.Plan.
//
// The webhook grants paid plans, so it fails CLOSED at every step: no secret → 503; bad signature →
// 401; unattributable event → 400. It can only ever affect the tenant whose id we stamped into the
// order's notes at checkout, and it can only grant a plan the catalog actually sells.

// handleBillingCheckout starts a purchase for the CALLING tenant.
func (d Deps) handleBillingCheckout(w http.ResponseWriter, r *http.Request, tenantID string) {
	if d.Razorpay == nil || !d.Razorpay.Configured() {
		writeJSON(w, http.StatusServiceUnavailable, errBody("payments aren't configured on this deployment (set RAZORPAY_KEY_ID / RAZORPAY_KEY_SECRET)"))
		return
	}
	var body struct {
		Plan  string `json:"plan"`
		Cycle string `json:"cycle"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, errBody("invalid request body"))
		return
	}
	if body.Plan == "" {
		body.Plan = platform.PlanGrowth // the only self-serve plan today
	}
	if body.Cycle == "" {
		body.Cycle = string(billing.Monthly)
	}
	item, err := billing.Lookup(body.Plan, billing.Cycle(body.Cycle))
	if err != nil {
		// Enterprise / an invented cycle lands here — talk-to-us, never a card.
		writeJSON(w, http.StatusBadRequest, errBody(err.Error()))
		return
	}
	order, err := d.Razorpay.CreateOrder(r.Context(), tenantID, item)
	if err != nil {
		respond(w, nil, err)
		return
	}
	writeJSON(w, http.StatusOK, order)
}

// handleBillingWebhook is Razorpay → us. Public by necessity, signed by requirement.
func (d Deps) handleBillingWebhook(w http.ResponseWriter, r *http.Request) {
	if d.Razorpay == nil || d.Razorpay.WebhookSecret == "" {
		// No secret means we CANNOT tell a real payment from a stranger's POST. Refuse to guess.
		writeJSON(w, http.StatusServiceUnavailable, errBody("billing webhook is not configured"))
		return
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errBody("could not read body"))
		return
	}
	// Verify against the EXACT bytes received — never a re-marshalled struct.
	if !billing.VerifyWebhook(raw, r.Header.Get("X-Razorpay-Signature"), d.Razorpay.WebhookSecret) {
		writeJSON(w, http.StatusUnauthorized, errBody("bad signature"))
		return
	}
	ev, err := billing.ParseEvent(raw)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errBody(err.Error()))
		return
	}
	plan, changes := billing.PlanAfter(ev)
	if !changes {
		// An event we deliberately don't act on (an authorization, an unknown type). 200 so Razorpay
		// stops retrying — acknowledged, not applied.
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "applied": false})
		return
	}
	t, err := d.Store.GetTenant(r.Context(), ev.TenantID)
	if err != nil {
		respond(w, nil, err)
		return
	}
	if t.ID == "" {
		writeJSON(w, http.StatusBadRequest, errBody("unknown tenant in webhook notes"))
		return
	}
	prev := t.Plan
	if prev == plan {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "applied": false, "reason": "already on " + plan})
		return
	}
	t.Plan = plan
	if err := d.Store.PutTenant(r.Context(), t); err != nil {
		respond(w, nil, err)
		return
	}
	// Money moved a plan — that is exactly the kind of decision the ledger exists for.
	if d.Recorder != nil {
		d.Recorder.Record("plan changed", "billing",
			map[string]any{"tenant_id": t.ID, "from": prev, "to": plan, "event": string(ev.Kind), "ref": ev.Ref},
			"billing webhook (signature-verified)")
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "applied": true, "plan": plan})
}
