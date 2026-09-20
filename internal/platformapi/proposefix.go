package platformapi

import (
	"context"

	"github.com/ClatTribe/tsengine/internal/detect"
	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// proposefix.go: findings that arrive by ingest reach the approval desk too.
//
// THE GAP. Remediation was proposed only in runner.RescanTenant — the engine scan path. The five
// credential-free ingest handlers (vercel, deviceposture, tprm, osint, saasposture) stored findings and
// stopped there. A workspace seeded through them produced 6 findings and 0 actions; GET /v1/approvals
// returned []. Nothing reached the Inbox.
//
// Those are the paths a customer uses FIRST, because they need no OAuth app and no cloud credentials.
// So the surfaces most likely to produce someone's first findings were the ones where the
// human-in-the-loop approval loop never started — while the dashboard told them, in these words,
// "TensorShield is triaging these and will prepare fixes you can approve".
//
// # The desk still decides
//
// This proposes and submits through the EXISTING Submitter (already wired in cmd/platform); it does
// not apply. Everything downstream is unchanged: hitl.Desk queues
// anything at or above the gate tier, honours the kill-switch, and remains the only route to
// connector.Apply (§18.2 inv. 3). A tier-1 ticket auto-delivering is the desk's existing behaviour,
// not something introduced here.
//
// # Why dedup is not optional
//
// Posture is re-posted. A device inventory that syncs daily would, without a guard, file a fresh
// ticket for the same unencrypted laptop every single day — and an inbox that cries wolf is worse than
// one that stays empty, because the customer stops opening it. Nothing else in the propose path dedups
// (the runner re-proposes on every rescan), so this cannot lean on a guard upstream.

// proposeForFindings runs ingested findings through the remediation proposer and submits what it
// produces to the desk. Returns how many were submitted.
//
// Best-effort throughout: a proposal failure must never fail the ingest that produced the finding. The
// finding is already stored and visible; a missing ticket is recoverable, a rejected ingest is not.
func (d Deps) proposeForFindings(ctx context.Context, tenantID string, findings []types.Finding) int {
	// Ingested posture findings have no asset record; remediate.Propose's default case turns
	// those into a generic ticket, which is the right shape: a human reads it and acts.
	return d.proposeForFindingsOn(ctx, tenantID, platform.Asset{TenantID: tenantID}, findings)
}

// proposeForFindingsOn is proposeForFindings against a KNOWN asset. It exists for the ingests that
// do have one — the HRIS join runs per workspace asset — because remediate keys its identity
// runbooks (and the live account-suspend promotion) on the asset's type and provider, and a leaver's
// still-enabled account should reach the desk as a gated suspend, not as a generic ticket.
func (d Deps) proposeForFindingsOn(ctx context.Context, tenantID string, asset platform.Asset, findings []types.Finding) int {
	if d.ProposeFix == nil || d.Submitter == nil || len(findings) == 0 {
		return 0
	}
	asset.TenantID = tenantID

	// What is already covered. Keyed by detect.Key (rule|endpoint) — the same key the incident
	// detector and the fix-verifier use, so all three agree on what "the same finding" means, and a
	// re-posted snapshot whose finding ids differ still matches.
	covered := map[string]bool{}
	if existing, err := d.Store.ListActions(ctx, tenantID); err == nil {
		for _, a := range existing {
			for _, k := range a.FindingKeys {
				covered[k] = true
			}
		}
	}

	submitted := 0
	for _, f := range findings {
		key := detect.Key(f)
		if covered[key] {
			continue // already has an action — re-posting posture must not re-file it
		}
		act, ok := d.ProposeFix(f, asset)
		if !ok {
			continue
		}
		act.TenantID = tenantID
		act.FindingID = f.ID
		// Stamp the stable key so retest.Verify can confirm the fix later — an action nobody can
		// verify is a ticket, not a remediation.
		act.FindingKeys = []string{key}
		if _, err := d.Submitter.Submit(ctx, act); err != nil {
			continue
		}
		covered[key] = true // guard within this batch too: two findings can share a key
		submitted++
	}
	return submitted
}
