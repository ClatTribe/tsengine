package platformapi

import (
	"context"
	"testing"

	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/ledger"
	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// proofDeps builds a tenant with one asset and the given findings.
func proofDeps(t *testing.T, ownershipVerified bool, findings ...types.Finding) (Deps, string) {
	t.Helper()
	ctx := context.Background()
	st := store.NewMemory()
	const tenantID = "t1"
	if err := st.PutTenant(ctx, platform.Tenant{ID: tenantID}); err != nil {
		t.Fatalf("put tenant: %v", err)
	}
	a := platform.Asset{ID: "a1", TenantID: tenantID, Type: "web_application", Target: "shop.example.com", Meta: map[string]string{}}
	if ownershipVerified {
		a.Meta["ownership_verified"] = "true"
	}
	if err := st.PutAsset(ctx, a); err != nil {
		t.Fatalf("put asset: %v", err)
	}
	for _, f := range findings {
		if err := st.PutFinding(ctx, tenantID, f); err != nil {
			t.Fatalf("put finding: %v", err)
		}
	}
	return Deps{Store: st, Recorder: ledger.NewRecorder()}, tenantID
}

func unprovenSQLi(id string) types.Finding {
	return types.Finding{
		ID: id, Tool: "nuclei", RuleID: "sqli-error-based", Title: "SQL injection in search",
		Endpoint: "https://shop.example.com/search?q=", Severity: types.SeverityHigh,
		VerificationStatus: types.VerificationPatternMatch, CWE: []string{"CWE-89"},
	}
}

// The edge that joins the personas: an unproven high finding on an OWNED target is nominated for proof.
func TestProofQueue_NominatesUnprovenFindingOnOwnedTarget(t *testing.T) {
	d, tid := proofDeps(t, true, unprovenSQLi("f1"))
	q := d.ProofQueue(context.Background(), tid)
	if len(q) != 1 {
		t.Fatalf("want 1 nomination, got %d", len(q))
	}
	if q[0].FindingID != "f1" || q[0].Class != "sqli" {
		t.Errorf("got %+v, want the sqli finding routed for proof", q[0])
	}
}

// Fail-closed: without ownership evidence we are not permitted to probe anything, so the queue is
// empty. This must hold even though the finding itself is a perfectly good candidate.
func TestProofQueue_UnverifiedOwnershipNominatesNothing(t *testing.T) {
	d, tid := proofDeps(t, false, unprovenSQLi("f1"))
	if q := d.ProofQueue(context.Background(), tid); len(q) != 0 {
		t.Errorf("got %d nominations without ownership verification, want 0 (fail closed)", len(q))
	}
}

// A proven finding has no doubt left — nominating it again would spend an exploit attempt on a
// settled question.
func TestProofQueue_AlreadyVerifiedIsNotRenominated(t *testing.T) {
	f := unprovenSQLi("f1")
	f.VerificationStatus = types.VerificationVerified
	d, tid := proofDeps(t, true, f)
	if q := d.ProofQueue(context.Background(), tid); len(q) != 0 {
		t.Errorf("got %d nominations for an already-proven finding, want 0", len(q))
	}
}

// The kill-switch halts autonomous work. Nominating targets for exploitation is exactly what it
// exists to stop, even though nothing is executed at this step.
func TestRecordProofQueue_KillSwitchHaltsNomination(t *testing.T) {
	ctx := context.Background()
	d, tid := proofDeps(t, true, unprovenSQLi("f1"))
	if n := d.RecordProofQueue(ctx, tid); n != 1 {
		t.Fatalf("baseline: want 1 nomination, got %d", n)
	}
	tn, _ := d.Store.GetTenant(ctx, tid)
	tn.AgentsHalted = true
	if err := d.Store.PutTenant(ctx, tn); err != nil {
		t.Fatal(err)
	}
	if n := d.RecordProofQueue(ctx, tid); n != 0 {
		t.Errorf("halted tenant nominated %d, want 0 — the kill-switch must freeze this too", n)
	}
}

// The gap between "found" and "proved" must be visible in the signed record, not implicit.
func TestRecordProofQueue_SignsIntoTheLedger(t *testing.T) {
	d, tid := proofDeps(t, true, unprovenSQLi("f1"))
	before := d.Recorder.Len()
	if n := d.RecordProofQueue(context.Background(), tid); n != 1 {
		t.Fatalf("want 1 nomination, got %d", n)
	}
	if d.Recorder.Len() <= before {
		t.Error("nominating findings for proof must be recorded — the found-vs-proved gap should be auditable")
	}
}

// A pass with nothing to settle costs nothing and records nothing.
func TestRecordProofQueue_QuietWhenNothingToProve(t *testing.T) {
	d, tid := proofDeps(t, true)
	before := d.Recorder.Len()
	if n := d.RecordProofQueue(context.Background(), tid); n != 0 {
		t.Errorf("want 0 nominations on a clean tenant, got %d", n)
	}
	if d.Recorder.Len() != before {
		t.Error("a pass with nothing to prove should not add ledger noise")
	}
}
