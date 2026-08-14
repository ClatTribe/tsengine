package runner

import (
	"context"
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/internal/connector"
	"github.com/ClatTribe/tsengine/internal/detect"
	"github.com/ClatTribe/tsengine/internal/retest"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

// ══ THE LOOP, RUNNING ════════════════════════════════════════════════════════════════════════════
//
// find → fix → prove it is dead. These drive the whole arc through RescanTenant, because the merge
// logic being correct in isolation is not the same as the monitoring pass actually invoking it.

// appliedFix stores a tenant with one APPLIED remediation claiming to have closed a finding.
func appliedFix(t *testing.T, st store.Store, key string) {
	t.Helper()
	ctx := context.Background()
	_ = st.PutTenant(ctx, platform.Tenant{ID: "t1"})
	_ = st.PutAsset(ctx, platform.Asset{ID: "a1", TenantID: "t1", Type: "workspace", Target: "acme"})
	_ = st.PutAction(ctx, platform.Action{
		ID: "act-1", TenantID: "t1", Status: platform.ActApplied, FindingKeys: []string{key},
	})
}

func actionVerification(t *testing.T, st store.Store) *platform.FixVerification {
	t.Helper()
	acts, err := st.ListActions(context.Background(), "t1")
	if err != nil || len(acts) == 0 {
		t.Fatalf("no actions: %v", err)
	}
	return acts[0].Verification
}

// THE ONE THAT MATTERS: the rescan says the finding is gone, but re-running the exploit shows it still
// works. The pass must end with still_exploitable, not fixed — otherwise we tell a customer a live
// hole is closed.
func TestRescanTenant_ReattackOverridesAFalseFixed(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	sc := &togglingScanner{Open: false} // the scanner no longer reports it → rescan says "fixed"
	appliedFix(t, st, "operate::stale-account|acme")

	n := 0
	var askedFor []string
	svc := &Service{
		Store: st, Connectors: connector.NewRegistry(), Tokens: fakeTokens{},
		Scanner: sc, NewID: func() string { n++; return itoa(n) },
		Detector: &detect.Detector{Store: st, NewID: func() string { n++; return itoa(n) }},
		Reattacker: func(_ context.Context, _ string, keys []string) map[string]retest.ReattackVerdict {
			askedFor = keys
			out := map[string]retest.ReattackVerdict{}
			for _, k := range keys {
				out[k] = retest.ReattackVerdict{Exploitable: true, Verified: true,
					Evidence: "the canary was still reflected"}
			}
			return out
		},
	}
	if _, err := svc.RescanTenant(ctx, "t1"); err != nil {
		t.Fatal(err)
	}
	if len(askedFor) == 0 {
		t.Fatal("the re-attacker was never asked about any finding key — the loop does not run")
	}
	v := actionVerification(t, st)
	if v == nil {
		t.Fatal("the applied fix got no verification at all")
	}
	if v.Status != retest.StatusStillExploitable {
		t.Fatalf("status = %q, want still_exploitable — a live exploit must override a clean rescan", v.Status)
	}
	if v.Method != retest.MethodReattack {
		t.Errorf("method = %q, want reattack", v.Method)
	}
}

// The happy path: both kinds of evidence agree, so the customer gets the strongest claim available.
func TestRescanTenant_BothAgreeYieldsClosedWithProof(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	appliedFix(t, st, "operate::stale-account|acme")

	n := 0
	svc := &Service{
		Store: st, Connectors: connector.NewRegistry(), Tokens: fakeTokens{},
		Scanner: &togglingScanner{Open: false}, NewID: func() string { n++; return itoa(n) },
		Detector: &detect.Detector{Store: st, NewID: func() string { n++; return itoa(n) }},
		Reattacker: func(_ context.Context, _ string, keys []string) map[string]retest.ReattackVerdict {
			out := map[string]retest.ReattackVerdict{}
			for _, k := range keys {
				out[k] = retest.ReattackVerdict{Exploitable: false, Verified: true}
			}
			return out
		},
	}
	if _, err := svc.RescanTenant(ctx, "t1"); err != nil {
		t.Fatal(err)
	}
	v := actionVerification(t, st)
	if v == nil || v.Status != retest.StatusClosedWithProof {
		t.Fatalf("want closed_with_proof, got %+v", v)
	}
	// Status alone is too weak an assertion: the "both agree" branch and the "exploit dead but the
	// scanner still sees it" branch BOTH return closed_with_proof, differing only in evidence. Assert
	// the agreement wording, so this test can actually tell them apart — the first version could not,
	// and a mutation that dropped the fresh rescan verdict slipped past it.
	if !strings.Contains(v.Evidence, "not just absence") {
		t.Errorf("evidence does not reflect that BOTH checks agreed: %q", v.Evidence)
	}
	if strings.Contains(strings.ToLower(v.Evidence), "partial") {
		t.Errorf("a full agreement was reported as partial: %q", v.Evidence)
	}
}

// No re-attacker wired → today's behaviour exactly. The feature must be additive, not a change to
// every existing deployment's verdicts.
func TestRescanTenant_NoReattackerKeepsRescanBehaviour(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	appliedFix(t, st, "operate::stale-account|acme")

	n := 0
	svc := &Service{
		Store: st, Connectors: connector.NewRegistry(), Tokens: fakeTokens{},
		Scanner: &togglingScanner{Open: false}, NewID: func() string { n++; return itoa(n) },
		Detector: &detect.Detector{Store: st, NewID: func() string { n++; return itoa(n) }},
	}
	if _, err := svc.RescanTenant(ctx, "t1"); err != nil {
		t.Fatal(err)
	}
	v := actionVerification(t, st)
	if v != nil && v.Method == retest.MethodReattack {
		t.Error("a deployment with no re-attacker produced a re-attack verdict")
	}
}

// Only APPLIED actions' keys are re-attacked. Probing findings nobody has tried to fix would spend
// live requests against a customer's system for no verification value.
func TestAppliedFindingKeys_OnlyAppliedActions(t *testing.T) {
	got := appliedFindingKeys([]platform.Action{
		{Status: platform.ActApplied, FindingKeys: []string{"b", "a"}},
		{Status: platform.ActPendingApproval, FindingKeys: []string{"never"}},
		{Status: platform.ActApplied, FindingKeys: []string{"a", ""}}, // dupe + empty
	})
	if len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Errorf("keys = %v, want a sorted, de-duplicated [a b] from applied actions only", got)
	}
	for _, k := range got {
		if k == "never" {
			t.Error("a key from an unapplied action was queued for re-attack")
		}
	}
}
