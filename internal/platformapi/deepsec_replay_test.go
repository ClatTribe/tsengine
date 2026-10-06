package platformapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ClatTribe/tsengine/internal/connector"
	"github.com/ClatTribe/tsengine/internal/runner"
	"github.com/ClatTribe/tsengine/internal/secret"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/internal/tool"
	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

const tenantOpenAIKey = "sk-tenant-own-openai-key-0000000000"

// outputScanner is a replayer that also returns a run summary, as the engine runner does.
type outputScanner struct {
	replayScanner
	summary any
	calls   int
}

func (o *outputScanner) ReplayToolWithOutput(_ context.Context, a platform.Asset, name string, args tool.Args, _ string) ([]types.Finding, any, error) {
	o.calls++
	o.gotAsset, o.gotTool, o.gotArgs = a, name, args
	return o.findings, o.summary, o.err
}

func deepsecDeps(t *testing.T, sc runner.ScanRunner, llm *platform.LLMConfig, mutate func(*platform.Tenant)) (http.Handler, store.Store) {
	t.Helper()
	st := store.NewMemory()
	ctx := context.Background()
	vault, err := secret.NewAESGCM(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	ten := platform.Tenant{ID: "t1", Name: "Acme"}
	if llm != nil {
		ref, _ := vault.Seal(tenantOpenAIKey)
		llm.KeyRef = ref
		ten.LLM = llm
	}
	if mutate != nil {
		mutate(&ten)
	}
	_ = st.PutTenant(ctx, ten)
	_ = st.PutAsset(ctx, platform.Asset{ID: "r1", TenantID: "t1", Type: "repository", Target: "https://github.com/acme/api"})
	h := NewHandler(Deps{
		Store: st, Connectors: connector.NewRegistry(), Token: "platform-tok", Vault: vault,
		Runner: &runner.Service{Store: st, Scanner: sc},
		NewID:  func() string { return "rp1" },
	})
	return h, st
}

func openai() *platform.LLMConfig { return &platform.LLMConfig{Provider: "openai", Model: "gpt-5.5"} }

func TestDeepsecReplay_RefusesWithoutTheTenantsOwnOpenAIKey(t *testing.T) {
	for name, llm := range map[string]*platform.LLMConfig{
		"no key":      nil,
		"anthropic":   {Provider: "anthropic", Model: "claude-opus-5"},
		"self-hosted": {Provider: "openai", Model: "llama", BaseURL: "http://localhost:11434/v1"},
	} {
		sc := &outputScanner{}
		h, _ := deepsecDeps(t, sc, llm, func(ten *platform.Tenant) { ten.Plan = "growth" })
		rec := do(h, "POST", "/v1/replay", "t1", `{"asset_id":"r1","tool":"deepsec","args":{"max_cost_usd":5}}`)
		if rec.Code != http.StatusBadRequest || sc.calls != 0 {
			t.Errorf("%s: deepsec must not run (code %d, calls %d)", name, rec.Code, sc.calls)
		}
		if !strings.Contains(rec.Body.String(), "OpenAI key") {
			t.Errorf("%s: the refusal must say how to fix it: %s", name, rec.Body.String())
		}
	}
}

func TestDeepsecReplay_RequiresACap(t *testing.T) {
	sc := &outputScanner{}
	h, _ := deepsecDeps(t, sc, openai(), nil)
	rec := do(h, "POST", "/v1/replay", "t1", `{"asset_id":"r1","tool":"deepsec"}`)
	if rec.Code != http.StatusBadRequest || sc.calls != 0 || !strings.Contains(rec.Body.String(), "max_cost_usd") {
		t.Fatalf("a review without a cap must be refused: %d %s", rec.Code, rec.Body.String())
	}
}

// The key comes from the tenant's sealed config and nowhere else — a caller-supplied _api_key is dropped.
func TestDeepsecReplay_UsesTheTenantKeyNotACallersAndMeters(t *testing.T) {
	sc := &outputScanner{summary: map[string]any{"cost_usd": 3.25, "cost_known": true, "model": "gpt-5.5",
		"reviewed_files": 12, "pending_files": 0}}
	h, st := deepsecDeps(t, sc, openai(), nil)
	rec := do(h, "POST", "/v1/replay", "t1",
		`{"asset_id":"r1","tool":"deepsec","args":{"max_cost_usd":5,"_api_key":"sk-attacker-chosen"}}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	if got := sc.gotArgs["_api_key"]; got != tenantOpenAIKey {
		t.Fatalf("deepsec must run on the tenant's own key, got %v", got)
	}
	if strings.Contains(rec.Body.String(), tenantOpenAIKey) {
		t.Fatal("the response leaked the tenant's key")
	}
	rows, _ := st.ListAISpend(context.Background(), "t1")
	if len(rows) != 1 || rows[0].Kind != "deepsec" || !rows[0].CostKnown || rows[0].USD != 3.25 {
		t.Fatalf("the run must be metered from its summary, got %+v", rows)
	}
	var resp map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp["summary"] == nil {
		t.Fatal("the engineer must see the run summary (cost, files reviewed)")
	}
}

func TestDeepsecReplay_ClampsTheCapToTheRemainingBudgetAndSaysSo(t *testing.T) {
	sc := &outputScanner{summary: map[string]any{"cost_usd": 1.0, "cost_known": true}}
	h, st := deepsecDeps(t, sc, openai(), func(ten *platform.Tenant) { ten.MonthlyAIBudgetUSD = 20 })
	_ = st.PutAISpend(context.Background(), platform.AISpend{ID: "s0", TenantID: "t1", At: time.Now().UTC(), Kind: "investigate",
		Surface: "estate", USD: 15, CostKnown: true})
	rec := do(h, "POST", "/v1/replay", "t1", `{"asset_id":"r1","tool":"deepsec","args":{"max_cost_usd":50}}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	if got, _ := sc.gotArgs["max_cost_usd"].(float64); got > 5.0001 {
		t.Fatalf("the cap must be lowered to the $5 left, got %v", sc.gotArgs["max_cost_usd"])
	}
	if !strings.Contains(rec.Body.String(), "was lowered") {
		t.Fatalf("a lowered cap must be stated: %s", rec.Body.String())
	}
}

func TestDeepsecReplay_ChoiceAndKillSwitchStopIt(t *testing.T) {
	for name, m := range map[string]func(*platform.Tenant){
		"deterministic": func(ten *platform.Tenant) { ten.AIMode = platform.AIModeDeterministic },
		"halted":        func(ten *platform.Tenant) { ten.AgentsHalted = true },
	} {
		sc := &outputScanner{}
		h, _ := deepsecDeps(t, sc, openai(), m)
		rec := do(h, "POST", "/v1/replay", "t1", `{"asset_id":"r1","tool":"deepsec","args":{"max_cost_usd":5}}`)
		if rec.Code != http.StatusForbidden || sc.calls != 0 {
			t.Errorf("%s: must refuse with 403, got %d (calls %d)", name, rec.Code, sc.calls)
		}
	}
}

// A run that errors still recorded spend — cost unknown, never zero.
func TestDeepsecReplay_FailedRunIsStillMetered(t *testing.T) {
	sc := &outputScanner{}
	sc.err = errors.New("deepsec process: exit status 1")
	h, st := deepsecDeps(t, sc, openai(), nil)
	rec := do(h, "POST", "/v1/replay", "t1", `{"asset_id":"r1","tool":"deepsec","args":{"max_cost_usd":5}}`)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("%d", rec.Code)
	}
	rows, _ := st.ListAISpend(context.Background(), "t1")
	if len(rows) != 1 || rows[0].CostKnown {
		t.Fatalf("a failed run must be counted with its cost unknown, got %+v", rows)
	}
}

// Internal args are stripped for every tool, not only deepsec.
func TestReplay_StripsInternalArgsForEveryTool(t *testing.T) {
	sc := &outputScanner{}
	h, _ := deepsecDeps(t, sc, nil, nil)
	rec := do(h, "POST", "/v1/replay", "t1", `{"asset_id":"r1","tool":"semgrep","args":{"_api_key":"x","config":"p/ci"}}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	if _, ok := sc.gotArgs["_api_key"]; ok || sc.gotArgs["config"] != "p/ci" {
		t.Fatalf("internal args must be stripped and the rest kept: %v", sc.gotArgs)
	}
	var resp map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if _, ok := resp["summary"]; ok {
		t.Fatal("a non-metered tool's raw Output must not ride the response")
	}
}
