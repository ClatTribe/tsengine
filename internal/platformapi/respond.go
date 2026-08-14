package platformapi

import (
	"context"

	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

// respond.go closes the RESPONSE gap for event-driven incidents.
//
// THE GAP. Twelve ingest paths — identity events, cloud drift/CDR, OSINT, device posture, SaaS, TPRM,
// the data warehouse — open an incident by calling IncidentOpener.OpenFor directly. Each fires the
// Alerter (a human learns of it) but NONE put the AI engineer on it. Only the scheduled scan does
// (AutoReviewAfterScan). So a posted identity event — impossible travel into an admin account, the
// classic takeover sequence — opens an incident, pings Slack, and the engineer never investigates. We
// alert; we do not respond. That is precisely the half a 24/7 SOC team otherwise covers.
//
// RespondToIncidents is the detect.Responder: when OpenFor opens a NEW incident, the engineer reviews
// the estate in light of it — the same gated review the scan path runs, now reachable between scans.
//
// DETACHED, because the caller is on an ingest REQUEST. An LLM review takes seconds to minutes; running
// it inline would hang POST /v1/identity/events for the duration. So the work runs in a goroutine on a
// cancellation-detached context, and the ingest returns immediately. Best-effort throughout — a review
// failure is logged and swallowed, never surfaced to the ingest caller (the interface's contract).
//
// It reuses AutoReviewAfterScan verbatim, so the economic gate is identical: a tenant's OWN LLM key runs
// on any plan, the operator-global model only for AI-entitled plans. A Free tenant with no key of its
// own triggers no operator spend here either.
func (d Deps) RespondToIncidents(ctx context.Context, tenantID string, opened []platform.Incident) {
	if len(opened) == 0 || d.Store == nil {
		return
	}
	// context.WithoutCancel: the ingest request's context is about to be cancelled when the handler
	// returns, but the review must outlive it. We keep values (tenant scoping, tracing) and drop only
	// the cancellation.
	bg := context.WithoutCancel(ctx)
	go d.runIncidentResponse(bg, tenantID, len(opened))
}

// runIncidentResponse is the synchronous core — the review the goroutine performs, and the seam the
// tests drive directly (a detached goroutine is not deterministically observable). It force-runs the
// gated auto-review by passing the opened count as openedIncidents, so the "something changed" trigger
// inside AutoReviewAfterScan fires.
func (d Deps) runIncidentResponse(ctx context.Context, tenantID string, openedCount int) {
	findings, err := d.Store.ListFindings(ctx, tenantID, store.FindingFilter{})
	if err != nil {
		return // best-effort: a store error must never crash a background responder
	}
	// openedCount > 0 is the "an incident opened" signal AutoReviewAfterScan gates on, so the review
	// runs even for a tenant that has triaged before — a NEW event-driven incident is exactly the change
	// that warrants a fresh look.
	d.AutoReviewAfterScan(ctx, tenantID, findings, openedCount)
}
