// Package hitl is the human-in-the-loop desk — the Kanpur human layer
// (docs/autonomous-team.md §3.4). It is the gate between an agent that *proposes* a
// remediation and a system that *applies* it: tier-0/1 actions auto-apply; tier ≥
// GateTier actions queue for a human to approve, edit, or reject. Every decision —
// auto-apply or human verdict — is written to the signed decision ledger, so the
// record shows exactly who let what happen and when.
package hitl

import (
	"context"
	"fmt"
	"time"

	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/ledger"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

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

// Submit routes a freshly proposed action: tier-gated actions queue for a human;
// everything else is applied immediately. Returns the action in its resulting state.
func (d *Desk) Submit(ctx context.Context, a platform.Action) (platform.Action, error) {
	if a.CreatedAt.IsZero() {
		a.CreatedAt = d.now()
	}
	if a.NeedsApproval() {
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
	return d.apply(ctx, a, "auto")
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
	for k, val := range v.Edit { // human edits ride onto the payload before apply
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
	return d.apply(ctx, a, v.Approver)
}

// apply executes an approved action and persists the applied state.
func (d *Desk) apply(ctx context.Context, a platform.Action, approver string) (platform.Action, error) {
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
	d.Recorder.Record(
		"hitl "+event,
		"hitl_decision",
		map[string]any{
			"action_id": a.ID, "finding_id": a.FindingID, "kind": a.Kind,
			"tier": a.Tier, "approver": approver,
		},
		fmt.Sprintf("action %s → %s (tier %d, approver %q)", a.ID, a.Status, a.Tier, approver),
	)
}
