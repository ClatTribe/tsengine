package platformapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ClatTribe/tsengine/internal/hitl"
	"github.com/ClatTribe/tsengine/internal/l2"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// THROUGH THE FRONT DOOR.
//
// Everything so far reaches the engineer through Go adapters. A customer reaches it over HTTP, and the
// gap between those two is exactly where the Shipped column's earlier lies lived: tsbench cvepatch
// graded codeagent.ProposePatch at 3/3 while the autofix ENDPOINT called the LLM with its own prompt
// and never touched codeagent. The benchmark described code no request could reach.
//
// So this drives POST /v1/l2/translate — the real route, the real handler, the real desk — and asks
// whether a customer request actually produces engineering work.

func httpEngineerDeps(t *testing.T, script []l2.Response) (Deps, string, *countingApplier) {
	t.Helper()
	ctx := context.Background()
	st := store.NewMemory()
	const tid = "t1"
	// Enterprise: the operator-global LLM is entitlement-gated, and a Free tenant must never spend it.
	if err := st.PutTenant(ctx, platform.Tenant{ID: tid, Plan: platform.PlanEnterprise}); err != nil {
		t.Fatal(err)
	}
	if err := st.PutAsset(ctx, platform.Asset{
		ID: "a1", TenantID: tid, Type: "web_application", Target: "shop.example.com",
		Meta: map[string]string{"ownership_verified": "true"},
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.PutFinding(ctx, tid, types.Finding{
		ID: "f-sqli", Tool: "nuclei", RuleID: "sqli-error-based", Severity: types.SeverityCritical,
		Title: "SQL injection in search", Endpoint: "https://shop.example.com/search?q=",
		VerificationStatus: types.VerificationPatternMatch, CWE: []string{"CWE-89"},
	}); err != nil {
		t.Fatal(err)
	}
	app := &countingApplier{}
	desk := &hitl.Desk{Store: st, Apply: app}
	return Deps{
		Store: st, Submitter: desk, Desk: desk,
		NewID:      func() string { return "a1" },
		LeadClient: &l2.MockClient{ModelName: "mock", Script: script},
	}, tid, app
}

func postTranslate(t *testing.T, d Deps, tid string) (int, map[string]any) {
	t.Helper()
	rec := httptest.NewRecorder()
	d.handleL2Translate(rec, httptest.NewRequest(http.MethodPost, "/v1/l2/translate", nil), tid)
	var body map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	return rec.Code, body
}

// THE ONE THAT MATTERS: a customer request produces a queued change, not just prose.
//
// This is the difference between an analyst and an engineer, asserted at the only layer a customer
// can observe.
func TestHTTP_ACustomerRequestProducesEngineeringWork(t *testing.T) {
	d, tid, _ := httpEngineerDeps(t, []l2.Response{
		jobCall("search_estate", map[string]any{"query": "critical unproven"}),
		jobCall("advance_phase", nil),
		jobCall("advance_phase", nil),
		jobCall("advance_phase", nil),
		jobCall("propose_fix", map[string]any{"finding_id": "f-sqli", "rationale": "Parameterize the query."}),
		jobCall("finish_scan", map[string]any{"executive_summary": "One injection; fix proposed."}),
	})
	code, body := postTranslate(t, d, tid)
	if code != http.StatusOK {
		t.Fatalf("POST /v1/l2/translate = %d, body %v", code, body)
	}

	acts, err := d.Store.ListActions(context.Background(), tid)
	if err != nil {
		t.Fatal(err)
	}
	if len(acts) == 0 {
		t.Fatal("NOT SHIPPED: a customer request ran the agent to completion and produced no queued " +
			"change — the belt works through Go adapters but not through the endpoint a customer hits")
	}
	if acts[0].FindingID != "f-sqli" {
		t.Errorf("queued change cites %q, not the finding it was about", acts[0].FindingID)
	}
	// The human is the gate for anything RISKY. Tier 0/1 (a ticket — informational and reversible)
	// auto-applying is the documented design, so the invariant to assert is the tiered one: nothing at
	// or above platform.GateTier may be applied without a human (§18.2 inv. 3).
	for _, a := range acts {
		if a.Tier >= platform.GateTier && a.Status == platform.ActApplied {
			t.Errorf("HUMAN BYPASSED: tier-%d action %s was applied by an HTTP request with no approval",
				a.Tier, a.ID)
		}
	}
}

// The endpoint must report what actually happened. A run that stalled or blew its budget and is
// reported as a clean result is how a customer concludes their estate was handled.
func TestHTTP_ReportsTheRealStopReason(t *testing.T) {
	d, tid, _ := httpEngineerDeps(t, []l2.Response{
		jobCall("search_estate", map[string]any{"query": "x"}),
	}) // script runs out; never calls finish_scan
	code, body := postTranslate(t, d, tid)
	if code != http.StatusOK {
		t.Fatalf("code=%d body=%v", code, body)
	}
	if got, _ := body["stop_reason"].(string); got == string(l2.StopFinished) {
		t.Error("DISHONEST: the endpoint reported 'finished' for a run that never called finish_scan")
	} else if got == "" {
		t.Error("the endpoint returned no stop_reason — a customer cannot tell a complete run from an " +
			"abandoned one")
	}
}

// The economic invariant, at the door: a Free tenant with no key of its own must not spend the
// operator's LLM budget. Asserted here because it is the endpoint, not the adapter, that enforces it.
func TestHTTP_FreeTenantCannotSpendOperatorLLM(t *testing.T) {
	d, tid, _ := httpEngineerDeps(t, []l2.Response{
		jobCall("finish_scan", map[string]any{"executive_summary": "x"}),
	})
	ctx := context.Background()
	tn, _ := d.Store.GetTenant(ctx, tid)
	tn.Plan = platform.PlanFree
	if err := d.Store.PutTenant(ctx, tn); err != nil {
		t.Fatal(err)
	}
	code, _ := postTranslate(t, d, tid)
	if code == http.StatusOK {
		t.Error("ECONOMIC GATE OPEN: a Free tenant with no key of its own drove the operator-funded LLM")
	}
}

// A tenant with no findings must not burn a model call to say so.
func TestHTTP_NoFindingsCostsNoModelCall(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	const tid = "empty"
	if err := st.PutTenant(ctx, platform.Tenant{ID: tid, Plan: platform.PlanEnterprise}); err != nil {
		t.Fatal(err)
	}
	mc := &l2.MockClient{ModelName: "mock", Script: []l2.Response{
		jobCall("finish_scan", map[string]any{"executive_summary": "x"}),
	}}
	d := Deps{Store: st, NewID: func() string { return "a1" }, LeadClient: mc}

	code, _ := postTranslate(t, d, tid)
	if code != http.StatusOK {
		t.Fatalf("an empty estate should answer cleanly, got %d", code)
	}
	if len(mc.Systems) != 0 {
		t.Errorf("an empty estate still made %d model call(s) — the customer pays to be told there is "+
			"nothing to do", len(mc.Systems))
	}
}
