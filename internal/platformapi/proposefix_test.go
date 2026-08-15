package platformapi

import (
	"context"
	"testing"

	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// Findings that arrive by ingest reach the approval desk too.
//
// Remediation used to be proposed only in the engine scan path, so the five credential-free ingest
// handlers stored findings and stopped. A workspace seeded through them had 6 findings and 0 actions —
// and those are the paths a customer uses first.

// fakeDesk records what was submitted without applying anything.
type fakeDesk struct {
	got []platform.Action
	err error
}

func (f *fakeDesk) Submit(_ context.Context, a platform.Action) (platform.Action, error) {
	if f.err != nil {
		return a, f.err
	}
	f.got = append(f.got, a)
	return a, nil
}

// ticketProposer stands in for remediate.Propose: it always produces a ticket, as the real
// proposer's default case does for a finding with no asset.
func ticketProposer(f types.Finding, _ platform.Asset) (platform.Action, bool) {
	return platform.Action{ID: "act-" + f.ID, Kind: platform.ActFileTicket, Tier: 1}, true
}

func depsWithDesk(t *testing.T) (Deps, *fakeDesk) {
	t.Helper()
	desk := &fakeDesk{}
	return Deps{Store: store.NewMemory(), ProposeFix: ticketProposer, Submitter: desk}, desk
}

func TestProposeForFindings_IngestedFindingReachesTheDesk(t *testing.T) {
	d, desk := depsWithDesk(t)
	f := types.Finding{
		ID: "dp-1", RuleID: "deviceposture::disk-unencrypted", Tool: "deviceposture",
		Severity: types.SeverityHigh, Endpoint: "device:mac-1",
	}
	if n := d.proposeForFindings(context.Background(), "ten-1", []types.Finding{f}); n != 1 {
		t.Fatalf("submitted %d, want 1 — an ingested finding never reached the approval desk", n)
	}
	if len(desk.got) != 1 {
		t.Fatalf("desk received %d actions", len(desk.got))
	}
	got := desk.got[0]
	if got.TenantID != "ten-1" {
		t.Errorf("action tenant = %q, want ten-1", got.TenantID)
	}
	if got.FindingID != "dp-1" {
		t.Errorf("action does not cite the finding it resolves: %+v", got)
	}
	// Without a stable key the fix can never be re-tested — that makes it a ticket, not a remediation.
	if len(got.FindingKeys) != 1 {
		t.Error("the action carries no finding key, so retest.Verify could never confirm the fix")
	}
}

// THE FLOOD GUARD. Posture is re-posted — a device inventory syncing daily would file a fresh ticket
// for the same unencrypted laptop every day. An inbox that cries wolf is worse than an empty one.
func TestProposeForFindings_DoesNotRefileOnRepostedPosture(t *testing.T) {
	d, desk := depsWithDesk(t)
	ctx := context.Background()
	f := types.Finding{
		ID: "dp-1", RuleID: "deviceposture::disk-unencrypted", Tool: "deviceposture",
		Severity: types.SeverityHigh, Endpoint: "device:mac-1",
	}
	// First ingest files a ticket, and the desk persists it.
	_ = d.proposeForFindings(ctx, "ten-1", []types.Finding{f})
	for _, a := range desk.got {
		if err := d.Store.PutAction(ctx, a); err != nil {
			t.Fatal(err)
		}
	}
	// The same posture re-posted tomorrow, with a different finding id (snapshots regenerate ids).
	again := f
	again.ID = "dp-99"
	if n := d.proposeForFindings(ctx, "ten-1", []types.Finding{again}); n != 0 {
		t.Errorf("re-posted posture filed %d duplicate ticket(s) — the inbox would fill with the same "+
			"laptop every day until the customer stopped opening it", n)
	}
}

// Two findings in ONE batch that share a key must produce one action, not two.
func TestProposeForFindings_DedupsWithinABatch(t *testing.T) {
	d, desk := depsWithDesk(t)
	f := types.Finding{ID: "a", RuleID: "r", Tool: "t", Endpoint: "device:mac-1"}
	g := types.Finding{ID: "b", RuleID: "r", Tool: "t", Endpoint: "device:mac-1"} // same key
	if n := d.proposeForFindings(context.Background(), "ten-1", []types.Finding{f, g}); n != 1 {
		t.Errorf("submitted %d for two findings sharing a key, want 1", n)
	}
	if len(desk.got) != 1 {
		t.Errorf("desk received %d actions", len(desk.got))
	}
}

// ── THE REFUSALS ─────────────────────────────────────────────────────────────────────────────────

// Unwired → no-op. A deployment without a proposer must behave exactly as before, not error.
func TestProposeForFindings_NoOpWhenUnwired(t *testing.T) {
	f := []types.Finding{{ID: "x", RuleID: "r", Endpoint: "e"}}
	if n := (Deps{Store: store.NewMemory()}).proposeForFindings(context.Background(), "ten-1", f); n != 0 {
		t.Errorf("unwired deps submitted %d", n)
	}
	// Proposer but no desk: still a no-op, never a half-done submit.
	d := Deps{Store: store.NewMemory(), ProposeFix: ticketProposer}
	if n := d.proposeForFindings(context.Background(), "ten-1", f); n != 0 {
		t.Errorf("deps with no submitter submitted %d", n)
	}
}

// A desk error must not fail the ingest that produced the finding. The finding is already stored and
// visible; a missing ticket is recoverable, a rejected ingest is not.
func TestProposeForFindings_DeskErrorIsSurvivable(t *testing.T) {
	desk := &fakeDesk{err: context.DeadlineExceeded}
	d := Deps{Store: store.NewMemory(), ProposeFix: ticketProposer, Submitter: desk}
	f := []types.Finding{{ID: "x", RuleID: "r", Endpoint: "e"}}
	if n := d.proposeForFindings(context.Background(), "ten-1", f); n != 0 {
		t.Errorf("counted %d submitted despite the desk erroring", n)
	}
}

// A proposer that declines (no sensible remediation for this class) files nothing.
func TestProposeForFindings_RespectsAProposerThatDeclines(t *testing.T) {
	desk := &fakeDesk{}
	d := Deps{
		Store:     store.NewMemory(),
		Submitter: desk,
		ProposeFix: func(types.Finding, platform.Asset) (platform.Action, bool) {
			return platform.Action{}, false
		},
	}
	if n := d.proposeForFindings(context.Background(), "ten-1", []types.Finding{{ID: "x", RuleID: "r", Endpoint: "e"}}); n != 0 {
		t.Errorf("submitted %d when the proposer declined", n)
	}
}
