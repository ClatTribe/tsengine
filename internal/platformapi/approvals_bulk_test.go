package platformapi

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/pkg/platform"
)

// Bulk approval is where a gate would quietly get weaker. These hold the properties that stop it: it
// is a faster keyboard, not a lighter check, and it never rounds a failure away.

// A failure must survive into the response. Fifty approvals where six fail delivery reported as
// "50 approved" leaves someone believing fifty tickets were filed when forty-four were — worse off
// than if they had been told.
func TestBulkDetail_NeverRoundsFailuresAway(t *testing.T) {
	got := bulkDetail(44, 6, true)
	if !strings.Contains(got, "44") || !strings.Contains(got, "6") {
		t.Errorf("a partial failure lost a number: %q", got)
	}
	if !strings.Contains(strings.ToLower(got), "did not go through") {
		t.Errorf("the failure is not stated plainly: %q", got)
	}
}

// Total failure must not read like partial success.
func TestBulkDetail_TotalFailureIsPlain(t *testing.T) {
	got := bulkDetail(0, 12, true)
	if strings.Contains(got, "approved") {
		t.Errorf("nothing succeeded but the message says approved: %q", got)
	}
}

// The clean case reads cleanly — no phantom failure count.
func TestBulkDetail_CleanRun(t *testing.T) {
	got := bulkDetail(7, 0, true)
	if strings.Contains(strings.ToLower(got), "did not") {
		t.Errorf("a clean run mentions failures: %q", got)
	}
	if !strings.Contains(got, "7") {
		t.Errorf("the count is missing: %q", got)
	}
}

// Reject must not be described as approve. The verb is the whole meaning of the sentence.
func TestBulkDetail_RejectSaysRejected(t *testing.T) {
	if got := bulkDetail(3, 0, false); !strings.Contains(got, "rejected") {
		t.Errorf("a rejection was described as %q", got)
	}
}

// A repeated id must be decided once. Deciding twice would fail the second time on an action that is
// no longer pending, which reads as an error the user did not cause.
func TestDedupeIDs_HandlesRepeatsAndBlanks(t *testing.T) {
	got := dedupeIDs([]string{"a", "b", "a", "", "  ", " c ", "b"})
	if len(got) != 3 {
		t.Fatalf("got %v, want 3 unique ids", got)
	}
	seen := map[string]bool{}
	for _, id := range got {
		if seen[id] {
			t.Errorf("duplicate survived: %q", id)
		}
		if strings.TrimSpace(id) == "" {
			t.Error("a blank id survived")
		}
		seen[id] = true
	}
	if !seen["c"] {
		t.Error("a padded id was dropped rather than trimmed")
	}
}

// The batch is bounded. Each decision may file a ticket or write to a customer's cloud, so this is
// real outbound work — an unbounded batch would hold a worker for minutes.
func TestBulkLimit_IsBoundedButUsable(t *testing.T) {
	if maxBulkDecisions < 50 {
		t.Errorf("maxBulkDecisions=%d is too small to clear a morning queue, which is the point",
			maxBulkDecisions)
	}
	if maxBulkDecisions > 1000 {
		t.Errorf("maxBulkDecisions=%d lets one request perform a thousand live deliveries",
			maxBulkDecisions)
	}
}

// THE ONE THAT MATTERS. Bulk must route through the same Desk.Decide as a single approval — the
// kill-switch has to keep winning, an irreversible action still needs a named signature, and every
// decision is still signed individually. If this ever became a batch write it would be a way to get
// a weaker gate by selecting more checkboxes.
func TestBulkUsesTheSameGate(t *testing.T) {
	src := readSource(t, "approvals_bulk.go")
	if !strings.Contains(src, "d.Desk.Decide(") {
		t.Fatal("bulk approval does not call Desk.Decide — it has its own write path, which means the " +
			"kill-switch and the signature requirement can diverge from the single-approval path")
	}
	for _, forbidden := range []string{"PutAction(", "Apply.Apply(", "d.Store.PutAction"} {
		if strings.Contains(src, forbidden) {
			t.Errorf("bulk approval reaches past the desk via %s", forbidden)
		}
	}
}

// ── THE SAFETY PROOF, DRIVEN THROUGH THE HANDLER ─────────────────────────────────────────────────

// Bulk approval must not become a way to get a weaker gate by selecting more checkboxes. The
// kill-switch is the sharpest test of that: a human has deliberately frozen all automation, and a
// verdict — however many it covers — must not beat their decision (§18.2 inv. 7).
//
// A first attempt at this failed to prove anything: the seeded actions had already auto-applied, so
// the refusal came from "not pending" rather than from the halt. This drives a genuinely PENDING
// tier-2 action so the halt is the only thing that can stop it.
func TestBulkApprove_KillSwitchStillWins(t *testing.T) {
	h, st := setupLoop(t)
	ctx := context.Background()

	// Two more pending, gated actions alongside the harness's act1.
	for _, id := range []string{"act2", "act3"} {
		if err := st.PutAction(ctx, platform.Action{
			ID: id, TenantID: "t1", Tier: 2, Kind: platform.ActApplyConfig,
			Status: platform.ActPendingApproval,
		}); err != nil {
			t.Fatal(err)
		}
	}
	// The human freezes everything.
	if err := st.PutTenant(ctx, platform.Tenant{ID: "t1", Name: "Acme", AgentsHalted: true}); err != nil {
		t.Fatal(err)
	}

	rec := do(h, "POST", "/v1/approvals/bulk", "t1",
		`{"ids":["act1","act2","act3"],"approver":"cto@acme.com","approve":true}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("bulk decide: code %d body %s", rec.Code, rec.Body.String())
	}
	var res bulkDecisionResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
		t.Fatal(err)
	}
	if res.Succeeded != 0 {
		t.Fatalf("%d of 3 actions were approved while automation was halted — bulk approval is a way "+
			"round the kill-switch: %+v", res.Succeeded, res.Results)
	}
	if res.Failed != 3 {
		t.Errorf("failed=%d, want 3", res.Failed)
	}
	// And every one must still be pending afterwards — refused, not silently consumed.
	for _, id := range []string{"act1", "act2", "act3"} {
		got, err := st.GetAction(ctx, "t1", id)
		if err != nil {
			t.Fatal(err)
		}
		if got.Status != platform.ActPendingApproval {
			t.Errorf("%s is %s after a refused bulk approval — the verdict was partly applied", id, got.Status)
		}
	}
}

// The happy path still works, so the guard above is not passing because bulk is simply broken.
func TestBulkApprove_WorksWhenNotHalted(t *testing.T) {
	h, st := setupLoop(t)
	ctx := context.Background()
	_ = st.PutAction(ctx, platform.Action{
		ID: "act2", TenantID: "t1", Tier: 2, Kind: platform.ActApplyConfig,
		Status: platform.ActPendingApproval,
	})

	rec := do(h, "POST", "/v1/approvals/bulk", "t1",
		`{"ids":["act1","act2"],"approver":"cto@acme.com","approve":true}`)
	var res bulkDecisionResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &res)
	if res.Succeeded != 2 || res.Failed != 0 {
		t.Fatalf("a normal bulk approval did not go through: %+v", res)
	}
	got, _ := st.GetAction(ctx, "t1", "act2")
	if got.Approver != "cto@acme.com" {
		t.Errorf("the approver was not recorded on each action: %+v", got)
	}
}
