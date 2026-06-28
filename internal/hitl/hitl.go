// Package hitl is the human-in-the-loop desk — the Kanpur human layer
// (docs/autonomous-team.md §3.4). It is the gate between an agent that *proposes* a
// remediation and a system that *applies* it: tier-0/1 actions auto-apply; tier ≥
// GateTier actions queue for a human to approve, edit, or reject. Every decision —
// auto-apply or human verdict — is written to the signed decision ledger, so the
// record shows exactly who let what happen and when.
package hitl

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/ledger"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

// ErrHalted is returned when the tenant's kill-switch (Tenant.AgentsHalted, agentic-SMB
// spec OM-3 / TS-5) is engaged: no remediation is applied while halted, so the desk fails
// closed. A human disengages the switch before any action executes.
var ErrHalted = errors.New("hitl: agent actions are halted (kill-switch engaged) — disengage to apply")

// ErrNeedsHumanSignature is returned when an irreversible (T3) action would apply without a
// named human approver — the agentic-SMB spec (§3 / AGT-3 / TS-2) forbids it. The agent
// prepares; a human decides and signs.
var ErrNeedsHumanSignature = errors.New("hitl: an irreversible (T3) action requires a named human signature — it cannot auto-apply")

// autoApprover is the recorded approver for a tier-0/1 auto-applied action — i.e. NOT a
// human. A T3 action carrying this (or an empty approver) is refused.
const autoApprover = "auto"

// Applier executes an approved (or auto-approved) action against the real world — the
// remediate.Deliverer in production, a fake in tests. The desk never applies directly;
// it decides, then delegates, keeping the gate and the side-effect separate.
type Applier interface {
	Apply(ctx context.Context, a platform.Action) error
}

// Notifier is pinged when an action queues for human approval (satisfied by
// *notify.Slack). Optional + nil-safe — the desk calls it best-effort.
type Notifier interface {
	ApprovalNeeded(ctx context.Context, a platform.Action) error
}

// Desk is the approval gate over the store.
type Desk struct {
	Store    store.Store
	Apply    Applier
	Notify   Notifier         // optional; pinged when an action queues for approval
	Recorder *ledger.Recorder // optional; records every decision into the signed ledger
	Now      func() time.Time
}

func (d *Desk) now() time.Time {
	if d.Now != nil {
		return d.Now().UTC()
	}
	return time.Now().UTC()
}

// halted reports whether the tenant's kill-switch is engaged. A read error is treated as
// NOT halted — the switch must be deliberately set; a transient store error must not
// silently freeze a tenant (and the apply path stays gated by the human tier anyway).
func (d *Desk) halted(ctx context.Context, tenantID string) bool {
	t, err := d.Store.GetTenant(ctx, tenantID)
	return err == nil && t.AgentsHalted
}

// Submit routes a freshly proposed action: tier-gated actions queue for a human;
// everything else is applied immediately. Returns the action in its resulting state.
func (d *Desk) Submit(ctx context.Context, a platform.Action) (platform.Action, error) {
	if a.CreatedAt.IsZero() {
		a.CreatedAt = d.now()
	}
	// Kill-switch: while halted, even a tier-0/1 auto-apply does NOT execute — it queues
	// for a human, so nothing is lost and nothing acts. Disengaging + approving applies it.
	if a.NeedsApproval() || d.halted(ctx, a.TenantID) {
		a.Status = platform.ActPendingApproval
		if err := d.Store.PutAction(ctx, a); err != nil {
			return a, err
		}
		d.record("queued", a, "")
		// best-effort push to the human desk (Slack); a notify failure must not lose
		// the queued action — it's already persisted and visible via the API.
		if d.Notify != nil {
			_ = d.Notify.ApprovalNeeded(ctx, a)
		}
		return a, nil
	}
	return d.apply(ctx, a, autoApprover)
}

// Pending lists the tenant's actions awaiting a human decision (the desk queue).
func (d *Desk) Pending(ctx context.Context, tenantID string) ([]platform.Action, error) {
	return d.Store.PendingApprovals(ctx, tenantID)
}

// Verdict is a human's decision on a queued action.
type Verdict struct {
	Approver string
	Approve  bool
	Edit     map[string]any // optional payload overrides (e.g. tweak the PR branch)
}

// Decide records a human's verdict on a pending action. Approve → apply (via the
// Applier); reject → mark rejected. Either way the decision is signed into the ledger.
func (d *Desk) Decide(ctx context.Context, tenantID, actionID string, v Verdict) (platform.Action, error) {
	a, err := d.Store.GetAction(ctx, tenantID, actionID)
	if err != nil {
		return platform.Action{}, err
	}
	if a.Status != platform.ActPendingApproval {
		return a, fmt.Errorf("hitl: action %s is %s, not pending", actionID, a.Status)
	}
	if v.Approver == "" {
		return a, fmt.Errorf("hitl: a decision needs an approver")
	}
	a.Approver = v.Approver
	a.DecidedAt = d.now()
	// Human edits ride onto the payload before apply — but NEVER the effect-defining keys. An approver
	// may tweak presentational fields (a PR base/body, a ticket summary), but may not rewrite WHAT a
	// mutation does: `target` (the resource the connector writes) and `remediation_type` (the class it
	// routes on) are grounded in the finding at propose time. Without this, an approver could retarget a
	// reviewed "block public access on bucket-A" at bucket-B after it was queued under the original
	// description — an approval-integrity gap. New effect-defining keys MUST be added to protectedPayloadKeys.
	for k, val := range v.Edit {
		if protectedPayloadKeys[k] {
			continue
		}
		if a.Payload == nil {
			a.Payload = map[string]any{}
		}
		a.Payload[k] = val
	}
	if !v.Approve {
		a.Status = platform.ActRejected
		if err := d.Store.PutAction(ctx, a); err != nil {
			return a, err
		}
		d.record("rejected", a, v.Approver)
		return a, nil
	}
	// A rejection is safe while halted (no write); an approval-to-apply is not — the
	// kill-switch wins over the verdict. The action stays pending so the human can re-approve
	// once they disengage.
	if d.halted(ctx, tenantID) {
		return a, ErrHalted
	}
	return d.apply(ctx, a, v.Approver)
}

// protectedPayloadKeys are payload fields that DEFINE what a mutation does — the resource it targets and
// the remediation class the Deliverer/connector routes on. They are set (grounded in the finding) at
// propose time and must never be rewritten by an approver's Edit, so a reviewed action can't be silently
// retargeted between review and apply.
var protectedPayloadKeys = map[string]bool{"target": true, "remediation_type": true}

// apply executes an approved action and persists the applied state.
func (d *Desk) apply(ctx context.Context, a platform.Action, approver string) (platform.Action, error) {
	// T3 invariant (agentic-SMB spec §3 / AGT-3 / TS-2): an irreversible / legal action
	// NEVER auto-applies — only a named human can sign it. Defense-in-depth: Submit already
	// queues tier ≥ GateTier, but this guarantees the rule even if a future path (e.g. a
	// break-glass auto-apply added for low tiers) ever reaches apply without a human.
	if a.NeedsHumanSignature() && (approver == "" || approver == autoApprover) {
		a.Status = platform.ActPendingApproval
		_ = d.Store.PutAction(ctx, a)
		d.record("blocked_t3_needs_signature", a, approver)
		return a, ErrNeedsHumanSignature
	}
	// Backstop: no write path executes under an engaged kill-switch, whatever called us.
	if d.halted(ctx, a.TenantID) {
		a.Status = platform.ActPendingApproval
		_ = d.Store.PutAction(ctx, a)
		d.record("blocked_killswitch", a, approver)
		return a, ErrHalted
	}
	if d.Apply != nil {
		if err := d.Apply.Apply(ctx, a); err != nil {
			// keep it visible: the action stays pending/approved-but-failed, not silently lost
			a.Status = platform.ActApproved
			_ = d.Store.PutAction(ctx, a)
			d.record("apply_failed", a, approver)
			return a, fmt.Errorf("hitl: apply %s: %w", a.ID, err)
		}
	}
	a.Status = platform.ActApplied
	if a.DecidedAt.IsZero() {
		a.DecidedAt = d.now()
	}
	if err := d.Store.PutAction(ctx, a); err != nil {
		return a, err
	}
	d.record("applied", a, approver)
	return a, nil
}

// record writes one decision step into the signed ledger (nil-safe).
func (d *Desk) record(event string, a platform.Action, approver string) {
	meta := map[string]any{
		"action_id": a.ID, "finding_id": a.FindingID, "kind": a.Kind,
		"tier": a.Tier, "approver": approver,
	}
	// Record the effect-defining fields so the signed trail shows WHAT was applied (the resource +
	// remediation class), not just the action kind — an auditor can see the actual target.
	if a.Payload != nil {
		if t, ok := a.Payload["target"]; ok {
			meta["target"] = t
		}
		if rt, ok := a.Payload["remediation_type"]; ok {
			meta["remediation_type"] = rt
		}
	}
	d.Recorder.Record(
		"hitl "+event,
		"hitl_decision",
		meta,
		fmt.Sprintf("action %s → %s (tier %d, approver %q)", a.ID, a.Status, a.Tier, approver),
	)
}
