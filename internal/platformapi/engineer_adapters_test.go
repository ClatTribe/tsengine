package platformapi

import (
	"context"
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// recordingSubmitter captures what the agent queued, and asserts nothing was ever applied.
type recordingSubmitter struct{ queued []platform.Action }

func (r *recordingSubmitter) Submit(_ context.Context, a platform.Action) (platform.Action, error) {
	a.Status = platform.ActPendingApproval // what a tier-2 desk does
	r.queued = append(r.queued, a)
	return a, nil
}

func engineerDeps(t *testing.T, tenantID string, findings ...types.Finding) (Deps, *recordingSubmitter) {
	t.Helper()
	ctx := context.Background()
	st := store.NewMemory()
	if err := st.PutTenant(ctx, platform.Tenant{ID: tenantID}); err != nil {
		t.Fatalf("put tenant: %v", err)
	}
	if err := st.PutAsset(ctx, platform.Asset{
		ID: "a1", TenantID: tenantID, Type: "web_application", Target: "shop.example.com",
		Meta: map[string]string{"ownership_verified": "true"},
	}); err != nil {
		t.Fatalf("put asset: %v", err)
	}
	for _, f := range findings {
		if err := st.PutFinding(ctx, tenantID, f); err != nil {
			t.Fatalf("put finding: %v", err)
		}
	}
	sub := &recordingSubmitter{}
	n := 0
	return Deps{Store: st, Submitter: sub, NewID: func() string { n++; return "id" + string(rune('0'+n)) }}, sub
}

func sqliFinding(id string) types.Finding {
	return types.Finding{
		ID: id, Tool: "nuclei", RuleID: "sqli-error-based", Title: "SQL injection in search",
		Endpoint: "https://shop.example.com/search?q=", Severity: types.SeverityCritical,
		VerificationStatus: types.VerificationPatternMatch, CWE: []string{"CWE-89"},
	}
}

// The tool the product never had: answering "what do I have?".
func TestEstateSearch_FindsByTermAndFacet(t *testing.T) {
	d, _ := engineerDeps(t, "t1", sqliFinding("f1"), types.Finding{
		ID: "f2", Tool: "trivy", Title: "Outdated openssl", Severity: types.SeverityLow,
	})
	got, err := estateSearch{d: d, tenantID: "t1"}.Search(context.Background(), "critical unproven injection")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, "f1") {
		t.Errorf("the critical unproven SQLi should match:\n%s", got)
	}
	if strings.Contains(got, "f2") {
		t.Errorf("the low-severity finding should be filtered out by the critical facet:\n%s", got)
	}
}

// "Nothing matched" and "we have no data" look identical to an agent, and only one means the estate is
// clean. Conflating them would let the agent report a clean bill of health for an unscanned tenant.
func TestEstateSearch_DistinguishesEmptyEstateFromNoMatch(t *testing.T) {
	empty, _ := engineerDeps(t, "t1")
	got, _ := estateSearch{d: empty, tenantID: "t1"}.Search(context.Background(), "anything")
	if !strings.Contains(got, "NO findings recorded") || !strings.Contains(got, "not the same as being clean") {
		t.Errorf("an unscanned tenant must be reported as unscanned, got:\n%s", got)
	}

	withData, _ := engineerDeps(t, "t1", sqliFinding("f1"))
	got, _ = estateSearch{d: withData, tenantID: "t1"}.Search(context.Background(), "kubernetes")
	if !strings.Contains(got, "none matching these terms") {
		t.Errorf("a non-matching query on a populated estate must read differently, got:\n%s", got)
	}
}

// TENANT ISOLATION: the tenant is bound at construction, never taken from a tool argument, so there is
// no query an agent could craft to reach another tenant's findings (§18.2 inv. 2).
func TestEngineerAdapters_CannotReachAnotherTenant(t *testing.T) {
	ctx := context.Background()
	d, _ := engineerDeps(t, "t1", sqliFinding("f1"))
	if err := d.Store.PutTenant(ctx, platform.Tenant{ID: "t2"}); err != nil {
		t.Fatal(err)
	}
	if err := d.Store.PutFinding(ctx, "t2", types.Finding{ID: "secret", Title: "OTHER TENANT SECRET"}); err != nil {
		t.Fatal(err)
	}

	got, _ := estateSearch{d: d, tenantID: "t1"}.Search(ctx, "secret")
	if strings.Contains(got, "OTHER TENANT SECRET") || strings.Contains(got, "secret]") {
		t.Fatalf("estate search leaked another tenant's data:\n%s", got)
	}
	// And a fix cannot be proposed against it either.
	if _, err := (fixProposer{d: d, tenantID: "t1"}).ProposeFix(ctx, "secret", "x"); err == nil {
		t.Fatal("proposed a fix for another tenant's finding")
	}
}

// Proposing queues; it never applies. The agent gains a voice, not authority.
func TestFixProposer_QueuesAtTheDeskAndCarriesTheRationale(t *testing.T) {
	d, sub := engineerDeps(t, "t1", sqliFinding("f1"))
	id, err := fixProposer{d: d, tenantID: "t1"}.ProposeFix(context.Background(), "f1", "parameterise the query")
	if err != nil {
		t.Fatal(err)
	}
	if len(sub.queued) != 1 {
		t.Fatalf("want 1 queued action, got %d", len(sub.queued))
	}
	q := sub.queued[0]
	if q.Status == platform.ActApplied {
		t.Fatal("the agent's proposal was APPLIED — it must only ever queue")
	}
	if id == "" {
		t.Error("the action id must come back so the agent can refer to it")
	}
	if got, _ := q.Payload["agent_rationale"].(string); got != "parameterise the query" {
		t.Errorf("agent_rationale = %q, want the reviewer to see why", got)
	}
	// It must cite a real finding — that is the grounding the human relies on.
	if q.FindingID != "f1" {
		t.Errorf("FindingID = %q, want the cited finding", q.FindingID)
	}
}

// A hallucinated id must fail loudly, not become a queued action a human has to work out is fictional.
func TestFixProposer_RefusesAnUnknownFinding(t *testing.T) {
	d, sub := engineerDeps(t, "t1", sqliFinding("f1"))
	_, err := fixProposer{d: d, tenantID: "t1"}.ProposeFix(context.Background(), "f-does-not-exist", "x")
	if err == nil {
		t.Fatal("proposing a fix for a nonexistent finding should fail")
	}
	if len(sub.queued) != 0 {
		t.Fatal("nothing should have been queued")
	}
}

// The two refusals mean opposite things to the agent — "we cannot test this class" vs "you have not
// proven you own this" — so they must not be reported with the same message.
func TestProofRequester_DistinguishesItsTwoRefusals(t *testing.T) {
	ctx := context.Background()

	// Provable class, but no ownership-verified asset.
	st := store.NewMemory()
	_ = st.PutTenant(ctx, platform.Tenant{ID: "t1"})
	_ = st.PutAsset(ctx, platform.Asset{ID: "a1", TenantID: "t1", Target: "shop.example.com"}) // not verified
	_ = st.PutFinding(ctx, "t1", sqliFinding("f1"))
	unowned := Deps{Store: st}
	got, err := proofRequester{d: unowned, tenantID: "t1"}.RequestProof(ctx, "f1")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, "ownership-verified") {
		t.Errorf("want an ownership refusal, got %q", got)
	}

	// Ownership fine, but a class no driver can demonstrate.
	d, _ := engineerDeps(t, "t1", types.Finding{
		ID: "f2", Tool: "trivy", RuleID: "CVE-2024-1", Title: "Outdated libssl",
		Endpoint: "https://shop.example.com/", Severity: types.SeverityHigh,
		VerificationStatus: types.VerificationPatternMatch,
	})
	got, err = proofRequester{d: d, tenantID: "t1"}.RequestProof(ctx, "f2")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, "prove nothing either way") || strings.Contains(got, "ownership-verified") {
		t.Errorf("want a 'no driver can settle this' refusal distinct from the ownership one, got %q", got)
	}
}

// An un-retested action must never read as a confirmed fix.
func TestFixVerifier_UnretestedIsNotConfirmed(t *testing.T) {
	ctx := context.Background()
	d, _ := engineerDeps(t, "t1", sqliFinding("f1"))
	if err := d.Store.PutAction(ctx, platform.Action{ID: "act1", TenantID: "t1", Status: platform.ActApplied}); err != nil {
		t.Fatal(err)
	}
	got, err := fixVerifier{d: d, tenantID: "t1"}.VerifyStatus(ctx, "act1")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, "not re-tested") {
		t.Errorf("an applied-but-unverified fix must say so, got %q", got)
	}
}
