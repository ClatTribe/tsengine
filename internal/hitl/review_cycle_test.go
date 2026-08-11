package hitl

import (
	"context"
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/pkg/ledger"

	"github.com/ClatTribe/tsengine/pkg/platform"
)

// review_cycle_test.go covers the THIRD verdict end to end: "almost — change this".
//
// With only approve/reject, a reviewer who spots one wrong line has to destroy a proposal that was
// mostly right in order to say so. That trains rubber-stamping or disengagement, and both turn the
// human-in-the-loop gate into theatre. These tests pin the behaviour that makes the desk feel like a
// senior engineer reviewing a pull request rather than a signature box.

// The full cycle: queue → request changes → re-propose addressing the feedback → approve → apply.
func TestReviewCycle_ChangesRequestedThenReproposedThenApproved(t *testing.T) {
	app := &recordingApplier{}
	d, rec, st := newDesk(app)
	ctx := context.Background()

	orig := platform.Action{
		ID: "a1", TenantID: "t", Tier: 2, Kind: platform.ActOpenPR, Status: platform.ActProposed,
		Title: "fix SQL injection in user lookup",
		Diff:  "--- a/store/users.go\n+++ b/store/users.go\n@@ -5,1 +5,1 @@\n-\tdb.Query(q + name)\n+\tdb.Query(q, name)\n",
	}
	if _, err := d.Submit(ctx, orig); err != nil {
		t.Fatal(err)
	}

	// 1) the reviewer sends it back — NOT applied, NOT closed
	sent, err := d.Decide(ctx, "t", "a1", Verdict{
		Approver: "senior-eng", RequestChanges: true,
		Feedback: "parameterise the ORDER BY clause too, not just the WHERE",
	})
	if err != nil {
		t.Fatalf("request-changes should be a valid verdict: %v", err)
	}
	if sent.Status != platform.ActChangesRequested {
		t.Errorf("status = %q, want changes_requested", sent.Status)
	}
	if len(app.applied) != 0 {
		t.Fatal("requesting changes must NEVER apply")
	}
	if sent.Feedback == "" || sent.ReviewedBy != "senior-eng" {
		t.Errorf("the reviewer's note and identity must be recorded, got feedback=%q by=%q", sent.Feedback, sent.ReviewedBy)
	}
	// It is sent back, not decided — Approver/DecidedAt belong to a final verdict.
	if sent.Approver != "" || !sent.DecidedAt.IsZero() {
		t.Error("a changes-requested action is still open — it must not carry a final decision")
	}
	if !recorded(rec, "changes_requested") {
		t.Error("the verdict must be signed into the ledger like any other decision")
	}

	// 2) the agent re-proposes, addressing the feedback and citing what it supersedes
	revised := platform.Action{
		ID: "a2", TenantID: "t", Tier: 2, Kind: platform.ActOpenPR, Status: platform.ActProposed,
		Title:      "fix SQL injection in user lookup (revised)",
		Supersedes: "a1",
		Diff:       "--- a/store/users.go\n+++ b/store/users.go\n@@ -5,2 +5,2 @@\n-\tdb.Query(q + name + order)\n+\tdb.Query(q, name, order)\n",
	}
	if _, err := d.Submit(ctx, revised); err != nil {
		t.Fatal(err)
	}

	// 3) approved → applies
	dec, err := d.Decide(ctx, "t", "a2", Verdict{Approver: "senior-eng", Approve: true})
	if err != nil {
		t.Fatal(err)
	}
	if dec.Status != platform.ActApplied {
		t.Errorf("status = %q, want applied", dec.Status)
	}
	if len(app.applied) != 1 || app.applied[0] != "a2" {
		t.Errorf("applied = %v, want only the revised action", app.applied)
	}

	// The thread is reconstructible: the revision points back at what it replaced.
	got, err := st.GetAction(ctx, "t", "a2")
	if err != nil {
		t.Fatal(err)
	}
	if got.Supersedes != "a1" {
		t.Errorf("supersedes = %q, want a1 so the desk can show a review thread", got.Supersedes)
	}
}

// "Change this" with no "this" is indistinguishable from a rejection and gives the next proposal
// nothing to act on — so it is refused rather than silently accepted as an empty note.
func TestReviewCycle_RequestChangesNeedsFeedback(t *testing.T) {
	app := &recordingApplier{}
	d, _, _ := newDesk(app)
	ctx := context.Background()
	_, _ = d.Submit(ctx, platform.Action{ID: "a1", TenantID: "t", Tier: 2, Kind: platform.ActApplyConfig, Status: platform.ActProposed})

	if _, err := d.Decide(ctx, "t", "a1", Verdict{Approver: "eng", RequestChanges: true, Feedback: "   "}); err == nil {
		t.Error("requesting changes with empty feedback should be refused")
	}
	if len(app.applied) != 0 {
		t.Fatal("a refused verdict must not apply anything")
	}
}

// A malformed verdict with BOTH flags must fail safe: withhold the apply, never cause one.
func TestReviewCycle_RequestChangesWinsOverApprove(t *testing.T) {
	app := &recordingApplier{}
	d, _, _ := newDesk(app)
	ctx := context.Background()
	_, _ = d.Submit(ctx, platform.Action{ID: "a1", TenantID: "t", Tier: 2, Kind: platform.ActApplyConfig, Status: platform.ActProposed})

	got, err := d.Decide(ctx, "t", "a1", Verdict{
		Approver: "eng", Approve: true, RequestChanges: true, Feedback: "narrow the CIDR first",
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != platform.ActChangesRequested {
		t.Errorf("status = %q — an ambiguous verdict must withhold the apply, not perform it", got.Status)
	}
	if len(app.applied) != 0 {
		t.Fatal("an ambiguous verdict must NEVER apply")
	}
}

// A sent-back action is not re-decidable through the same door: it is no longer pending. This stops a
// second reviewer from approving something the first sent back without a fresh proposal.
func TestReviewCycle_ChangesRequestedIsNoLongerPending(t *testing.T) {
	app := &recordingApplier{}
	d, _, _ := newDesk(app)
	ctx := context.Background()
	_, _ = d.Submit(ctx, platform.Action{ID: "a1", TenantID: "t", Tier: 2, Kind: platform.ActApplyConfig, Status: platform.ActProposed})
	if _, err := d.Decide(ctx, "t", "a1", Verdict{Approver: "eng", RequestChanges: true, Feedback: "narrow it"}); err != nil {
		t.Fatal(err)
	}

	if _, err := d.Decide(ctx, "t", "a1", Verdict{Approver: "eng2", Approve: true}); err == nil {
		t.Error("a changes-requested action must not be approvable without a fresh proposal")
	}
	if len(app.applied) != 0 {
		t.Fatal("nothing should have been applied")
	}
	pend, _ := d.Pending(ctx, "t")
	for _, p := range pend {
		if p.ID == "a1" {
			t.Error("a sent-back action should not sit in the pending queue as if awaiting a first look")
		}
	}
}

// The reviewer must be able to SEE the change. An ActOpenPR whose diff is empty is a signature box.
func TestReviewCycle_CodeActionsCarryAReadableDiff(t *testing.T) {
	d, _, st := newDesk(&recordingApplier{})
	ctx := context.Background()
	_, _ = d.Submit(ctx, platform.Action{
		ID: "a1", TenantID: "t", Tier: 2, Kind: platform.ActOpenPR, Status: platform.ActProposed,
		Diff: "--- a/x.go\n+++ b/x.go\n@@ -1,1 +1,1 @@\n-bad\n+good\n",
	})
	got, err := st.GetAction(ctx, "t", "a1")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got.Diff, "-bad") || !strings.Contains(got.Diff, "+good") {
		t.Errorf("the diff must survive persistence so the reviewer can read it, got %q", got.Diff)
	}
}

// recorded reports whether the ledger captured a step mentioning action — the decision must be signed
// like any other (§18.2 inv. 4), not silently applied to the store.
func recorded(rec *ledger.Recorder, action string) bool {
	for _, s := range rec.Steps() {
		if strings.Contains(s.Thought, action) || strings.Contains(s.Tool, action) || strings.Contains(s.Observation, action) {
			return true
		}
	}
	return false
}
