package platformapi

import (
	"context"
	"encoding/json"
	"math"
	"sync"
	"testing"

	"github.com/ClatTribe/tsengine/internal/cloudengine"
	"github.com/ClatTribe/tsengine/internal/cloudsnap"
	"github.com/ClatTribe/tsengine/internal/connector"
	"github.com/ClatTribe/tsengine/internal/pentest"
	"github.com/ClatTribe/tsengine/internal/secret"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

const meterModel = "claude-sonnet-5-5"

// usageFake reports usage the way the real clients do: a cumulative counter on the client.
type usageFake struct {
	mu  sync.Mutex
	u   cloudengine.Usage
	per int64
}

func (f *usageFake) Generate(context.Context, string) (string, error) {
	f.mu.Lock()
	f.u.InputTokens += f.per
	f.mu.Unlock()
	return `{"tool":"finish","args":{"summary":"done"}}`, nil
}
func (f *usageFake) TotalUsage() cloudengine.Usage { f.mu.Lock(); defer f.mu.Unlock(); return f.u }
func (f *usageFake) ModelName() string             { return meterModel }

// silentFake reports no usage at all.
type silentFake struct{}

func (silentFake) Generate(context.Context, string) (string, error) { return "ok", nil }

func meterDeps(t *testing.T, tenants ...string) (Deps, *store.Memory) {
	t.Helper()
	st := store.NewMemory()
	for _, id := range tenants {
		_ = st.PutTenant(context.Background(), platform.Tenant{ID: id, Plan: platform.PlanEnterprise})
	}
	return Deps{Store: st, AgentLLM: &usageFake{per: 1000},
		AgentLLMFactory: func() pentest.SpecLLM { return &usageFake{per: 1000} }}, st
}

func spendRows(t *testing.T, st *store.Memory, tenant string) []platform.AISpend {
	t.Helper()
	rows, err := st.ListAISpend(context.Background(), tenant)
	if err != nil {
		t.Fatal(err)
	}
	return rows
}

func costOf(tokens int64) float64 {
	return cloudengine.EstimateCost(meterModel, cloudengine.Usage{InputTokens: tokens})
}

func near(a, b float64) bool { return math.Abs(a-b) < 1e-9 }

// THE GAP THIS CLOSES: a path nobody remembered to meter spent money the ceiling never saw. Every call
// through the resolve door is now a row, labelled where the caller said what it was.
func TestMeter_EveryCallThroughTheDoorIsRecorded(t *testing.T) {
	ctx := context.Background()
	d, st := meterDeps(t, "t1")
	llm := d.resolveAgentLLMForRole(aiKind(ctx, "code sweep", "code"), "t1", platform.RoleCode)
	_, _ = llm.Generate(ctx, "a")
	_, _ = llm.Generate(ctx, "b")

	rows := spendRows(t, st, "t1")
	if len(rows) != 2 {
		t.Fatalf("two calls must be two rows, got %d: %+v", len(rows), rows)
	}
	for _, r := range rows {
		if !r.PerCall || !r.CostKnown || r.Kind != "code sweep" || r.Surface != "code" || !near(r.USD, costOf(1000)) {
			t.Errorf("row: %+v (want one call's cost %.6f)", r, costOf(1000))
		}
	}
}

// A client that reports nothing is a call of UNKNOWN cost, never a free one.
func TestMeter_UnreportedUsageIsUnknownNotFree(t *testing.T) {
	ctx := context.Background()
	d, st := meterDeps(t, "t1")
	d.AgentLLM, d.AgentLLMFactory = silentFake{}, nil
	_, _ = d.resolveAgentLLM(ctx, "t1").Generate(ctx, "x")
	rows := spendRows(t, st, "t1")
	if len(rows) != 1 || rows[0].CostKnown || rows[0].USD != 0 || rows[0].Kind != "model call" {
		t.Fatalf("an unpriced call must be recorded as unknown: %+v", rows)
	}
}

// A run that prices itself is not billed twice, and a call after it is billed only for itself.
func TestMeter_SelfPricedRunIsNotCountedTwice(t *testing.T) {
	ctx := context.Background()
	d, st := meterDeps(t, "t1")
	llm := d.resolveAgentLLM(ctx, "t1")
	_, _ = llm.Generate(meteredRun(ctx), "inside the run")
	_, _ = llm.Generate(meteredRun(ctx), "inside the run")
	if rows := spendRows(t, st, "t1"); len(rows) != 0 {
		t.Fatalf("calls inside a self-priced run were recorded: %+v", rows)
	}
	_, _ = llm.Generate(ctx, "after")
	rows := spendRows(t, st, "t1")
	if len(rows) != 1 || !near(rows[0].USD, costOf(1000)) {
		t.Fatalf("the call after the run was billed for the run's tokens: %+v", rows)
	}
}

// Each tenant's run reads usage from a client no other tenant shares. On one shared counter, a delta
// taken across a run includes whatever another tenant spent in the meantime.
func TestMeter_TenantsDoNotBillEachOther(t *testing.T) {
	ctx := context.Background()
	d, st := meterDeps(t, "t1", "t2")
	a := d.resolveAgentLLM(ctx, "t1")
	b := d.resolveAgentLLM(ctx, "t2")
	_, _ = a.Generate(ctx, "1")
	_, _ = b.Generate(ctx, "2")
	_, _ = a.Generate(ctx, "3")

	sum := func(tenant string) float64 {
		s := 0.0
		for _, r := range spendRows(t, st, tenant) {
			s += r.USD
		}
		return s
	}
	if !near(sum("t1"), costOf(2000)) || !near(sum("t2"), costOf(1000)) {
		t.Fatalf("t1=%.6f (want %.6f) t2=%.6f (want %.6f) — one tenant was billed for another's calls",
			sum("t1"), costOf(2000), sum("t2"), costOf(1000))
	}
}

// The point of metering: the monthly ceiling now stops paths it used to be blind to.
func TestMeter_PerCallSpendReachesTheCeiling(t *testing.T) {
	ctx := context.Background()
	d, st := meterDeps(t, "t1")
	d.AgentLLMFactory = func() pentest.SpecLLM { return &usageFake{per: 10_000_000} }
	tn, _ := st.GetTenant(ctx, "t1")
	tn.MonthlyAIBudgetUSD = costOf(10_000_000) / 2
	_ = st.PutTenant(ctx, tn)

	llm := d.resolveAgentLLMForRole(aiKind(ctx, "exploit proposals", "pentest"), "t1", platform.RoleCode)
	if llm == nil {
		t.Fatal("under budget, a model should resolve")
	}
	_, _ = llm.Generate(ctx, "expensive")
	if again := d.resolveAgentLLM(ctx, "t1"); again != nil {
		t.Fatal("a call that spent past the ceiling did not stop the next resolve")
	}
}

// A resolve with no model stays nil, so every caller's "is AI available" check keeps meaning it.
func TestMeter_NoModelStaysNil(t *testing.T) {
	d, _ := meterDeps(t, "t1")
	d.AgentLLM, d.AgentLLMFactory = nil, nil
	if d.resolveAgentLLM(context.Background(), "t1") != nil {
		t.Fatal("a wrapped nil client reads as a configured model")
	}
}

// The cloud specialist prices its whole run; the wrapper must not add a row per call on top.
func TestMeter_CloudRunIsOneRow(t *testing.T) {
	d, st := meterDeps(t, "t1")
	d.Connectors, d.Token = connector.NewRegistry(), "platform-tok"
	rec := do(NewHandler(d), "POST", "/v1/cloud/investigate", "t1", `{"inventory":{"account_id":"1","provider":"aws"}}`)
	if rec.Code != 200 {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	rows := spendRows(t, st, "t1")
	if len(rows) != 1 || rows[0].PerCall || rows[0].Surface != "cloud" {
		t.Fatalf("a cloud run must be exactly one run row, got %+v", rows)
	}
}

// Calls are spend but not runs. A call that produces no outcome (the sweep's candidates) is NOT in the
// cost-per-proven-finding numerator — only runs can verify a finding — so it neither inflates that figure
// nor, when unpriced, withholds it. It is reported as its own number instead of disappearing.
func TestAIValue_CallsAreCountedApartFromRuns(t *testing.T) {
	ctx := context.Background()
	d, _ := meterDeps(t, "t1")
	d.Connectors, d.Token = connector.NewRegistry(), "platform-tok"
	d.recordAISpend(ctx, "t1", "code", "code", 1.0, true, meterModel, 2)
	d.putSpend(ctx, platform.AISpend{ID: spendID(), TenantID: "t1", At: nowUTC(), Kind: "code sweep", Surface: "code", USD: 0.5, CostKnown: true, PerCall: true})
	d.putSpend(ctx, platform.AISpend{ID: spendID(), TenantID: "t1", At: nowUTC(), Kind: "code sweep", Surface: "code", PerCall: true})

	s := aiValueSurface(t, d, "code")
	if s.Runs != 1 || s.Calls != 2 || s.UnknownCostCalls != 1 || !near(s.USD, 1.5) || !near(s.NoOutcomeUSD, 0.5) {
		t.Errorf("surface: %+v", s)
	}
	if s.CostPerVerified == nil || !near(*s.CostPerVerified, 0.5) {
		t.Errorf("cost per proven finding must be the RUN's spend over its proofs (1.00/2), not all spend: %+v", s.CostPerVerified)
	}
	// An unpriced RUN still withholds it: then the numerator itself is partial.
	d.putSpend(ctx, platform.AISpend{ID: spendID(), TenantID: "t1", At: nowUTC(), Kind: "code", Surface: "code", Verified: 1})
	if s := aiValueSurface(t, d, "code"); s.CostPerVerified != nil {
		t.Error("an unpriced run must withhold cost-per-proven-finding")
	}
}

func aiValueSurface(t *testing.T, d Deps, surface string) surfaceValue {
	t.Helper()
	var v aiValueView
	_ = json.Unmarshal(do(NewHandler(d), "GET", "/v1/ai-value", "t1", "").Body.Bytes(), &v)
	for _, s := range v.Surfaces {
		if s.Surface == surface {
			return s
		}
	}
	t.Fatalf("no %q surface in %+v", surface, v)
	return surfaceValue{}
}

// A fix the AI wrote is weighed against what writing it cost — and the fixes that did NOT close count in
// the cost too, so the figure is the price of a proven fix, not the price of the successes alone.
func TestAIValue_CostPerProvenFixCountsTheFailures(t *testing.T) {
	ctx := context.Background()
	d, st := meterDeps(t, "t1")
	d.Connectors, d.Token = connector.NewRegistry(), "platform-tok"
	fix := func(action string, usd float64, known bool) {
		d.putSpend(ctx, platform.AISpend{ID: spendID(), TenantID: "t1", At: nowUTC(), Kind: "fix patch", Surface: "code",
			USD: usd, CostKnown: known, PerCall: true, ActionID: action})
	}
	fix("a-closed", 0.40, true)
	fix("a-failed", 0.60, true)
	fix("a-pending", 0.20, true)
	_ = st.PutAction(ctx, platform.Action{ID: "a-closed", TenantID: "t1", Status: platform.ActApplied, Verification: &platform.FixVerification{Status: platform.FixStatusFixed}})
	_ = st.PutAction(ctx, platform.Action{ID: "a-failed", TenantID: "t1", Status: platform.ActApplied, Verification: &platform.FixVerification{Status: platform.FixStatusStillPresent}})
	_ = st.PutAction(ctx, platform.Action{ID: "a-pending", TenantID: "t1", Status: platform.ActApplied})

	s := aiValueSurface(t, d, "code")
	if s.FixesAttempted != 3 || s.VerifiedFixes != 1 {
		t.Fatalf("attempted/verified: %+v", s)
	}
	if s.CostPerVerifiedFix == nil || !near(*s.CostPerVerifiedFix, 1.20) {
		t.Fatalf("cost per proven fix must be ALL fix spend (1.20) over the one proven fix: %v", s.CostPerVerifiedFix)
	}
	if s.NoOutcomeUSD != 0 {
		t.Errorf("fix spend has an outcome and must not be counted as no-outcome: %+v", s)
	}
	// One unpriced fix call: the numerator is partial, so the figure is withheld.
	fix("a-closed", 0, false)
	if s := aiValueSurface(t, d, "code"); s.CostPerVerifiedFix != nil {
		t.Error("an unpriced fix call must withhold cost-per-proven-fix")
	}
}

// WIRING: the delivery-time patcher's calls carry the action they were spent on. Without this the fix
// columns are always zero and the view quietly reports that the AI never wrote a fix.
func TestPatchForAction_SpendCarriesTheAction(t *testing.T) {
	llm := &patchLLMUsage{patchLLM: &patchLLM{}}
	d, a, c := patchDeps(t, nil)
	d.AgentLLM = llm
	if _, _, err := d.PatchForAction(context.Background(), a, c, "gh-token"); err != nil {
		t.Fatal(err)
	}
	rows, _ := d.Store.ListAISpend(context.Background(), "t1")
	if len(rows) == 0 {
		t.Fatal("the patcher's model calls were not recorded")
	}
	for _, r := range rows {
		if r.ActionID != a.ID || r.Kind != "fix patch" {
			t.Errorf("row not tied to the action it was spent producing: %+v", r)
		}
	}
}

// patchLLMUsage is patchLLM that reports usage, as the real clients do.
type patchLLMUsage struct {
	*patchLLM
	n int64
}

func (p *patchLLMUsage) Generate(ctx context.Context, prompt string) (string, error) {
	p.n += 1000
	return p.patchLLM.Generate(ctx, prompt)
}
func (p *patchLLMUsage) TotalUsage() cloudengine.Usage { return cloudengine.Usage{InputTokens: p.n} }
func (p *patchLLMUsage) ModelName() string             { return meterModel }

// The other self-priced entry points: each run is one row, never one plus a row per call.
func TestMeter_EverySelfPricedRunIsOneRow(t *testing.T) {
	ctx := context.Background()
	check := func(t *testing.T, st *store.Memory, surface string) {
		t.Helper()
		rows := spendRows(t, st, "t1")
		if len(rows) != 1 || rows[0].PerCall || rows[0].Surface != surface {
			t.Fatalf("want exactly one %s run row, got %+v", surface, rows)
		}
	}
	t.Run("code on demand", func(t *testing.T) {
		d, st := meterDeps(t, "t1")
		d.Connectors, d.Token = connector.NewRegistry(), "platform-tok"
		body := `{"repo":"acme/api","findings":[{"id":"f1","tool":"semgrep","endpoint":"api/h.go:3"}],"source":{"api/h.go":"a\nb\nc"}}`
		if rec := do(NewHandler(d), "POST", "/v1/code/investigate", "t1", body); rec.Code != 200 {
			t.Fatalf("%d %s", rec.Code, rec.Body.String())
		}
		check(t, st, "code")
	})
	t.Run("cloud delegated", func(t *testing.T) {
		d, st := meterDeps(t, "t1")
		snaps := cloudsnap.NewMemStore()
		_ = snaps.Put(ctx, cloudsnap.Snapshot{TenantID: "t1", Inventory: []byte(`{"account_id":"1","provider":"aws"}`)})
		d.CloudSnapshots = snaps
		if _, err := d.cloudInvestigator("t1")(ctx, ""); err != nil {
			t.Fatal(err)
		}
		check(t, st, "cloud")
	})
	t.Run("code delegated", func(t *testing.T) {
		d, st := meterDeps(t, "t1")
		vault, _ := secret.NewAESGCM(make([]byte, 32))
		ref, _ := vault.Seal("ghp_test")
		_ = st.PutConnection(ctx, platform.Connection{ID: "c1", TenantID: "t1", Kind: platform.ConnGitHub, Account: "acme",
			SecretRef: ref, Config: map[string]string{"repo": "api"}, Status: platform.ConnActive})
		_ = st.PutFinding(ctx, "t1", types.Finding{ID: "f1", Tool: "semgrep", RuleID: "semgrep::sqli", Endpoint: "api/h.go:3"})
		d.Vault = vault
		if _, err := d.codeInvestigator("t1")(ctx, ""); err != nil {
			t.Fatal(err)
		}
		check(t, st, "code")
	})
}

// A fix written entirely on the tenant's own self-hosted model costs a KNOWN $0 (#1533), and that is a
// real price: the cost per proven fix is shown as $0.00, not withheld as if it were unknown. Withholding
// it would hide exactly the saving a free draft model exists to deliver.
func TestAIValue_SelfHostedFixIsAKnownZeroNotWithheld(t *testing.T) {
	ctx := context.Background()
	d, st := meterDeps(t, "t1")
	d.Connectors, d.Token = connector.NewRegistry(), "platform-tok"
	d.putSpend(ctx, platform.AISpend{ID: spendID(), TenantID: "t1", At: nowUTC(), Kind: "fix patch (draft)", Surface: "code",
		CostKnown: true, PerCall: true, ActionID: "a1", SelfHosted: true, Model: "qwen-local"})
	_ = st.PutAction(ctx, platform.Action{ID: "a1", TenantID: "t1", Status: platform.ActApplied, Verification: &platform.FixVerification{Status: platform.FixStatusFixed}})
	s := aiValueSurface(t, d, "code")
	if s.CostPerVerifiedFix == nil || *s.CostPerVerifiedFix != 0 {
		t.Fatalf("a self-hosted proven fix must show $0.00, not be withheld: %+v", s.CostPerVerifiedFix)
	}
	if s.SelfHosted != 1 {
		t.Errorf("the self-hosted row must be counted as such: %+v", s)
	}
}
