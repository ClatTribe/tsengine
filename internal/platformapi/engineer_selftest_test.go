package platformapi

import (
	"context"
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/internal/remediate"
	"github.com/ClatTribe/tsengine/internal/retest"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// engineer_selftest_test.go asks the question the benchmarks do not: does the AI Security Engineer
// actually WORK, task by task, through the real production wiring?
//
// The distinction matters and had been missed. Benchmarks grade quality in isolation — how good is
// triage, how good is localization. The tools were verified two ways: the catalogue exposes them (with
// NIL backings), and the adapters work (in isolation). Neither proves the path a real request takes:
//
//	agent tool → adapter → real store → real proposer → real HITL desk
//
// So every task here runs against a real store, real Deps and the real EngineerCatalog. No mocked
// adapters. A failure means a customer-visible path is broken, not that a score slipped.
//
// T4 (fix) needs a live model to produce a patch, so it is gated rather than faked: a self-test that
// pretends to exercise a path it cannot reach is worse than one that says it skipped.

// seedEngineerTenant builds a tenant with an ownership-verified asset and one unproven critical
// finding — the shape every task below operates on.
func seedEngineerTenant(t *testing.T) (Deps, string) {
	t.Helper()
	ctx := context.Background()
	st := store.NewMemory()
	const tid = "selftest"
	if err := st.PutTenant(ctx, platform.Tenant{ID: tid}); err != nil {
		t.Fatalf("tenant: %v", err)
	}
	if err := st.PutAsset(ctx, platform.Asset{
		ID: "a1", TenantID: tid, Type: "web_application", Target: "shop.example.com",
		Meta: map[string]string{"ownership_verified": "true"},
	}); err != nil {
		t.Fatalf("asset: %v", err)
	}
	if err := st.PutFinding(ctx, tid, types.Finding{
		ID: "f-sqli", Tool: "nuclei", RuleID: "sqli-error-based",
		Title: "SQL injection in search", Description: "Request data is concatenated into the query.",
		Endpoint: "https://shop.example.com/search?q=", Severity: types.SeverityCritical,
		VerificationStatus: types.VerificationPatternMatch, CWE: []string{"CWE-89"},
	}); err != nil {
		t.Fatalf("finding: %v", err)
	}
	// A low-severity decoy: triage must leave it alone.
	if err := st.PutFinding(ctx, tid, types.Finding{
		ID: "f-noise", Tool: "nuclei", RuleID: "server-version-banner",
		Title: "Server version in header", Endpoint: "https://shop.example.com/",
		Severity: types.SeverityLow, VerificationStatus: types.VerificationPatternMatch,
	}); err != nil {
		t.Fatalf("decoy: %v", err)
	}
	sub := &recordingSubmitter{}
	n := 0
	return Deps{Store: st, Submitter: sub, NewID: func() string { n++; return "id" + string(rune('a'+n)) }}, tid
}

func findingByID(t *testing.T, d Deps, tid, id string) types.Finding {
	t.Helper()
	fs, err := d.Store.ListFindings(context.Background(), tid, store.FindingFilter{})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	for _, f := range fs {
		if f.ID == id {
			return f
		}
	}
	t.Fatalf("no finding %s", id)
	return types.Finding{}
}

// T1 — TRIAGE. The gate that decides what reaches a human at all.
func TestEngineerWorks_T1_Triage(t *testing.T) {
	d, tid := seedEngineerTenant(t)
	real := findingByID(t, d, tid, "f-sqli")
	noise := findingByID(t, d, tid, "f-noise")

	if !remediate.WorthProposing(real) {
		t.Error("T1 BROKEN: a critical finding was triaged out — the engineer would never act on it")
	}
	if remediate.WorthProposing(noise) {
		t.Error("T1 BROKEN: low-severity noise was promoted into a human's approval queue")
	}
}

// T3 — ASSESS. An unproven finding must reach the offensive side, and the ownership gate must hold.
func TestEngineerWorks_T3_Assess(t *testing.T) {
	d, tid := seedEngineerTenant(t)
	got, err := (proofRequester{d: d, tenantID: tid}).RequestProof(context.Background(), "f-sqli")
	if err != nil {
		t.Fatalf("T3 BROKEN: %v", err)
	}
	if !strings.Contains(got, "Queued") {
		t.Errorf("T3 BROKEN: an unproven critical on an owned target was not routed for proof: %s", got)
	}
	// The honest half: a failed attempt must never read as an all-clear.
	if !strings.Contains(got, "proves nothing") {
		t.Errorf("T3 BROKEN: the result omits the not-proven caveat, which is how a failed exploit "+
			"becomes a false all-clear: %s", got)
	}
}

// T5 — VERIFY. An applied fix must be re-tested against a fresh scan, not taken on trust.
func TestEngineerWorks_T5_Verify(t *testing.T) {
	ctx := context.Background()
	d, tid := seedEngineerTenant(t)
	applied := platform.Action{
		ID: "act-1", TenantID: tid, Status: platform.ActApplied,
		FindingKeys: []string{"sqli-error-based|https://shop.example.com/search?q="},
	}
	if err := d.Store.PutAction(ctx, applied); err != nil {
		t.Fatal(err)
	}
	// The finding is GONE from the fresh scan → the fix held.
	verified := retest.Verify([]platform.Action{applied}, nil, timeNow())
	if len(verified) == 0 {
		t.Fatal("T5 BROKEN: an applied action with finding keys produced no verification at all")
	}
	if verified[0].Verification == nil || verified[0].Verification.Status != "fixed" {
		t.Errorf("T5 BROKEN: a finding absent from the fresh scan was not confirmed fixed: %+v", verified[0].Verification)
	}

	// And the inverse: still present → must NOT report fixed.
	still := retest.Verify([]platform.Action{applied}, []types.Finding{findingByID(t, d, tid, "f-sqli")}, timeNow())
	if len(still) > 0 && still[0].Verification != nil && still[0].Verification.Status == "fixed" {
		t.Error("T5 BROKEN: a finding STILL PRESENT was reported as fixed — the worst possible lie here")
	}
}

// T6 — ANSWER. The tool the product never had: query your own estate.
func TestEngineerWorks_T6_Answer(t *testing.T) {
	d, tid := seedEngineerTenant(t)
	got, err := (estateSearch{d: d, tenantID: tid}).Search(context.Background(), "critical unproven injection")
	if err != nil {
		t.Fatalf("T6 BROKEN: %v", err)
	}
	if !strings.Contains(got, "f-sqli") {
		t.Errorf("T6 BROKEN: the estate query did not surface the matching finding:\n%s", got)
	}
	if strings.Contains(got, "f-noise") {
		t.Errorf("T6 BROKEN: the critical filter did not exclude the low-severity decoy:\n%s", got)
	}
}

// T8 — HAND OFF. Work that is not ours must reach the desk as a ticket.
func TestEngineerWorks_T8_HandOff(t *testing.T) {
	d, tid := seedEngineerTenant(t)
	ref, err := (ticketFiler{d: d, tenantID: tid}).FileTicket(context.Background(),
		"Upgrade the vulnerable dependency", "The pinned version carries a published advisory.")
	if err != nil {
		t.Fatalf("T8 BROKEN: %v", err)
	}
	if ref == "" {
		t.Error("T8 BROKEN: no ticket reference returned — the agent cannot cite what it raised")
	}
	sub := d.Submitter.(*recordingSubmitter)
	if len(sub.queued) != 1 || sub.queued[0].Kind != platform.ActFileTicket {
		t.Errorf("T8 BROKEN: the ticket did not reach the desk as a file_ticket action: %+v", sub.queued)
	}
}

// THE WHOLE PATH. A fix proposal must travel agent tool → adapter → proposer → desk, and arrive
// pending approval rather than applied.
func TestEngineerWorks_ProposeReachesTheDeskUnapplied(t *testing.T) {
	d, tid := seedEngineerTenant(t)
	cat := d.EngineerCatalog(tid)

	var propose func(ctx context.Context, args map[string]any) string
	for _, tool := range cat {
		if tool.Schema.Name == "propose_fix" {
			tl := tool
			propose = func(ctx context.Context, args map[string]any) string {
				res, err := tl.Handler(ctx, args, nil)
				if err != nil {
					t.Fatalf("propose_fix handler: %v", err)
				}
				return res.Content
			}
		}
	}
	if propose == nil {
		t.Fatal("propose_fix is not in the catalogue — the engineer has no hands")
	}

	out := propose(context.Background(), map[string]any{
		"finding_id": "f-sqli", "rationale": "parameterise the query",
	})
	if !strings.Contains(strings.ToLower(out), "not applied") {
		t.Errorf("the tool must tell the agent plainly that nothing was applied, got: %s", out)
	}
	sub := d.Submitter.(*recordingSubmitter)
	if len(sub.queued) != 1 {
		t.Fatalf("the proposal did not reach the desk: %d queued", len(sub.queued))
	}
	if sub.queued[0].Status == platform.ActApplied {
		t.Fatal("SAFETY BREACH: the agent's proposal was APPLIED without a human — it may only ever queue")
	}
	if sub.queued[0].FindingID != "f-sqli" {
		t.Errorf("the queued action does not cite the finding it fixes (%q) — grounding is broken",
			sub.queued[0].FindingID)
	}
}

// A hallucinated finding id must never become a queued action a human has to work out is fictional.
func TestEngineerWorks_RefusesToActOnAnInventedFinding(t *testing.T) {
	d, tid := seedEngineerTenant(t)
	_, err := (fixProposer{d: d, tenantID: tid}).ProposeFix(context.Background(), "f-does-not-exist", "x")
	if err == nil {
		t.Fatal("GROUNDING BROKEN: proposed a fix for a finding that does not exist")
	}
	if len(d.Submitter.(*recordingSubmitter).queued) != 0 {
		t.Fatal("GROUNDING BROKEN: an invented finding produced a queued action")
	}
}
