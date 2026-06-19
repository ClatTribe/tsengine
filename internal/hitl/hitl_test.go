package hitl

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"

	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/ledger"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

// recordingApplier records what it was asked to apply.
type recordingApplier struct {
	applied []string
	fail    bool
}

func (r *recordingApplier) Apply(_ context.Context, a platform.Action) error {
	if r.fail {
		return errors.New("boom")
	}
	r.applied = append(r.applied, a.ID)
	return nil
}

func newDesk(app Applier) (*Desk, *ledger.Recorder, store.Store) {
	st := store.NewMemory()
	rec := ledger.NewRecorder()
	return &Desk{Store: st, Apply: app, Recorder: rec}, rec, st
}

// The kill-switch (Tenant.AgentsHalted) freezes the write path: a tier-1 auto-apply queues
// instead of executing, and even a human approval of a gated action is refused until the
// switch is disengaged.
func TestKillSwitchFreezesWritePath(t *testing.T) {
	ctx := context.Background()
	app := &recordingApplier{}
	d, _, st := newDesk(app)
	_ = st.PutTenant(ctx, platform.Tenant{ID: "t", Name: "Acme", AgentsHalted: true})

	// a tier-1 action that would normally auto-apply must QUEUE while halted (not lost)
	got, err := d.Submit(ctx, platform.Action{ID: "a1", TenantID: "t", Tier: 1, Kind: platform.ActOpenPR, Status: platform.ActProposed})
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != platform.ActPendingApproval {
		t.Fatalf("halted tier-1 action should queue, got status %s", got.Status)
	}
	if len(app.applied) != 0 {
		t.Fatalf("nothing must apply while halted, applied=%v", app.applied)
	}

	// approving the queued action while halted is refused (the switch wins over the verdict)
	if _, err := d.Decide(ctx, "t", "a1", Verdict{Approver: "boss@acme.com", Approve: true}); !errors.Is(err, ErrHalted) {
		t.Fatalf("approve while halted should return ErrHalted, got %v", err)
	}
	if len(app.applied) != 0 {
		t.Fatalf("still nothing applied while halted, applied=%v", app.applied)
	}

	// disengage → the same approval now applies
	_ = st.PutTenant(ctx, platform.Tenant{ID: "t", Name: "Acme", AgentsHalted: false})
	if _, err := d.Decide(ctx, "t", "a1", Verdict{Approver: "boss@acme.com", Approve: true}); err != nil {
		t.Fatal(err)
	}
	if len(app.applied) != 1 || app.applied[0] != "a1" {
		t.Fatalf("after disengage the action must apply, applied=%v", app.applied)
	}
}

// T3 (irreversible/legal) actions never auto-apply: Submit queues them, a direct
// auto-apply is refused with ErrNeedsHumanSignature, and only a NAMED human approval lands.
func TestTier3NeverAutoApplies(t *testing.T) {
	ctx := context.Background()
	app := &recordingApplier{}
	d, _, _ := newDesk(app)

	got, err := d.Submit(ctx, platform.Action{ID: "t3", TenantID: "t", Tier: platform.TierIrreversible, Status: platform.ActProposed})
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != platform.ActPendingApproval || len(app.applied) != 0 {
		t.Fatalf("a T3 action must queue, never auto-apply: status=%s applied=%v", got.Status, app.applied)
	}

	// a direct apply with the auto marker is refused (defense-in-depth)
	if _, err := d.apply(ctx, platform.Action{ID: "t3b", TenantID: "t", Tier: platform.TierIrreversible}, autoApprover); !errors.Is(err, ErrNeedsHumanSignature) {
		t.Fatalf("auto-applying a T3 action must return ErrNeedsHumanSignature, got %v", err)
	}
	if len(app.applied) != 0 {
		t.Fatalf("no T3 action may apply without a human, applied=%v", app.applied)
	}

	// a NAMED human approval applies it (the human signed)
	if _, err := d.Decide(ctx, "t", "t3", Verdict{Approver: "ciso@acme.com", Approve: true}); err != nil {
		t.Fatal(err)
	}
	if len(app.applied) != 1 || app.applied[0] != "t3" {
		t.Fatalf("a human-signed T3 action must apply, applied=%v", app.applied)
	}
}

func TestTier1AutoApplies(t *testing.T) {
	app := &recordingApplier{}
	d, rec, _ := newDesk(app)
	a := platform.Action{ID: "a1", TenantID: "t", Tier: 1, Kind: platform.ActOpenPR, Status: platform.ActProposed}

	got, err := d.Submit(context.Background(), a)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != platform.ActApplied {
		t.Errorf("tier-1 should auto-apply, got %s", got.Status)
	}
	if len(app.applied) != 1 || app.applied[0] != "a1" {
		t.Errorf("applier should have run once: %v", app.applied)
	}
	if rec.Len() == 0 {
		t.Error("auto-apply must be recorded in the ledger")
	}
}

func TestTier2GatesThenHumanApproves(t *testing.T) {
	app := &recordingApplier{}
	d, rec, st := newDesk(app)
	ctx := context.Background()
	a := platform.Action{ID: "a2", TenantID: "t", Tier: 2, Kind: platform.ActApplyConfig, Status: platform.ActProposed}

	// 1) submit → queues, does NOT apply
	got, _ := d.Submit(ctx, a)
	if got.Status != platform.ActPendingApproval {
		t.Fatalf("tier-2 should queue, got %s", got.Status)
	}
	if len(app.applied) != 0 {
		t.Fatal("tier-2 must NOT apply before a human decides")
	}
	pend, _ := d.Pending(ctx, "t")
	if len(pend) != 1 {
		t.Fatalf("want 1 pending, got %d", len(pend))
	}

	// 2) a human approves with an edit → applies, edit lands on the payload
	dec, err := d.Decide(ctx, "t", "a2", Verdict{Approver: "kanpur-analyst-1", Approve: true, Edit: map[string]any{"base": "release"}})
	if err != nil {
		t.Fatal(err)
	}
	if dec.Status != platform.ActApplied || dec.Approver != "kanpur-analyst-1" {
		t.Errorf("approved action wrong: %+v", dec)
	}
	if dec.Payload["base"] != "release" {
		t.Errorf("human edit did not land: %+v", dec.Payload)
	}
	if len(app.applied) != 1 {
		t.Errorf("approve should apply exactly once: %v", app.applied)
	}

	// 3) the whole decision trail is signed + verifiable
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	l := rec.Build(ledger.Meta{AgentKind: "hitl", Target: "t"})
	_ = ledger.Sign(l, "k", priv, l.StartedAt)
	if err := ledger.Verify(l, pub); err != nil {
		t.Errorf("decision ledger should verify: %v", err)
	}
	// queued + applied both recorded
	if rec.Len() < 2 {
		t.Errorf("want queued+applied steps, got %d", rec.Len())
	}
	_ = st
}

func TestRejectDoesNotApply(t *testing.T) {
	app := &recordingApplier{}
	d, _, _ := newDesk(app)
	ctx := context.Background()
	_, _ = d.Submit(ctx, platform.Action{ID: "a3", TenantID: "t", Tier: 2, Status: platform.ActProposed})

	dec, err := d.Decide(ctx, "t", "a3", Verdict{Approver: "analyst", Approve: false})
	if err != nil {
		t.Fatal(err)
	}
	if dec.Status != platform.ActRejected {
		t.Errorf("want rejected, got %s", dec.Status)
	}
	if len(app.applied) != 0 {
		t.Error("rejected action must never apply")
	}
}

func TestApplyFailureIsVisible(t *testing.T) {
	app := &recordingApplier{fail: true}
	d, _, _ := newDesk(app)
	ctx := context.Background()
	_, _ = d.Submit(ctx, platform.Action{ID: "a4", TenantID: "t", Tier: 2, Status: platform.ActProposed})

	_, err := d.Decide(ctx, "t", "a4", Verdict{Approver: "analyst", Approve: true})
	if err == nil {
		t.Fatal("a failed apply must surface an error, not silently succeed")
	}
	got, _ := d.Store.GetAction(ctx, "t", "a4")
	if got.Status == platform.ActApplied {
		t.Error("a failed apply must not be marked applied")
	}
}

func TestDecideGuards(t *testing.T) {
	d, _, _ := newDesk(&recordingApplier{})
	ctx := context.Background()
	// deciding a non-existent action errors
	if _, err := d.Decide(ctx, "t", "ghost", Verdict{Approver: "x", Approve: true}); err == nil {
		t.Error("deciding a missing action should error")
	}
	// approver required
	_, _ = d.Submit(ctx, platform.Action{ID: "a5", TenantID: "t", Tier: 2, Status: platform.ActProposed})
	if _, err := d.Decide(ctx, "t", "a5", Verdict{Approve: true}); err == nil {
		t.Error("a verdict without an approver should error")
	}
}
