package platformapi

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"strings"
	"time"

	"github.com/ClatTribe/tsengine/internal/cloudengine"
	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// aispend.go: one append-only row per AI run, so the monthly budget counts every run and the value view
// can weigh what was spent against what was proven.
//
// Before this the only spend record was AIAnalysis (one row per kind:scope, overwritten by a re-run, and
// not written at all for a run that returned nothing), and the cloud and code specialists recorded no
// dollar cost anywhere. So the cap under-counted repeat runs and never saw specialist runs.

// usageMeter reads a model client's cumulative usage. Absent → the run's cost is UNKNOWN, never zero.
func usageMeter(llm any) (func() (float64, bool), string) {
	ur, ok := llm.(cloudengine.UsageReporter)
	if !ok {
		return func() (float64, bool) { return 0, false }, ""
	}
	model := ""
	if mn, ok := llm.(cloudengine.ModelNamer); ok {
		model = mn.ModelName()
	}
	before := ur.TotalUsage()
	return func() (float64, bool) {
		after := ur.TotalUsage()
		delta := cloudengine.Usage{
			InputTokens: after.InputTokens - before.InputTokens, OutputTokens: after.OutputTokens - before.OutputTokens,
			CacheReadTokens: after.CacheReadTokens - before.CacheReadTokens,
		}
		if delta.Total() <= 0 {
			return 0, false
		}
		return cloudengine.EstimateCost(model, delta), true
	}, model
}

// recordAISpend appends one run's cost. Best-effort: a store failure loses the row and is logged; it never
// fails the run, whose output the customer already has.
func (d Deps) recordAISpend(ctx context.Context, tenantID, kind, surface string, usd float64, known bool, model string, verified int) {
	d.putSpend(ctx, platform.AISpend{
		ID: spendID(), TenantID: tenantID, At: time.Now().UTC(), Kind: kind, Surface: surface,
		USD: usd, CostKnown: known, Model: model, Verified: verified,
	})
}

func (d Deps) putSpend(ctx context.Context, e platform.AISpend) {
	if d.Store == nil {
		return
	}
	tenantID, kind, known := e.TenantID, e.Kind, e.CostKnown
	if !known {
		e.USD = 0
	}
	// The one place every spend row passes through, so a self-hosted run is free no matter which meter
	// priced it (the per-call wrapper, a run-level meter, or the Lead's own estimate).
	if d.selfHostedModel(ctx, tenantID, e.Model) {
		e.USD, e.CostKnown, e.SelfHosted = 0, true, true
	}
	if err := d.Store.PutAISpend(ctx, e); err != nil {
		slog.Warn("ai spend not recorded", "tenant", tenantID, "kind", kind, "err", err.Error())
	}
}

func countVerified(fs []types.Finding) int {
	n := 0
	for _, f := range fs {
		if f.VerificationStatus == types.VerificationVerified {
			n++
		}
	}
	return n
}

// spendID is unique per run, never derived from the clock alone. A clock-only id collides when two runs
// are recorded in the same tick (macOS timer granularity makes that routine), and the store keys by id, so
// the second would overwrite the first — the exact under-count this record exists to remove.
func spendID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return "spend-" + time.Now().UTC().Format("20060102T150405.000000000") + "-" + hex.EncodeToString(b)
}

// selfHostedModels is the set of model names (lower-cased) served by the tenant's OWN self-hosted configs
// — the default or a per-role override whose provider is "ollama" or "openai-compat" (the providers the
// settings page labels self-hosted; a cloud provider's base URL is cleared on save, so SelfHosted() is
// exactly that set). Spend rows are matched on the model name, because a row knows which model ran and
// not which config built it.
//
// Applied when a row is WRITTEN and again when rows are READ (the monthly budget, the value view), so
// rows recorded at the default frontier rate before this rule existed stop charging the budget at once
// rather than at the next month boundary.
func selfHostedModels(t platform.Tenant) map[string]bool {
	out := map[string]bool{}
	add := func(c *platform.LLMConfig) {
		if c != nil && c.SelfHosted() {
			if m := strings.ToLower(strings.TrimSpace(c.Model)); m != "" {
				out[m] = true
			}
		}
	}
	add(t.LLM)
	for _, c := range t.LLMRoles {
		add(c)
	}
	return out
}

// selfHostedModel reports whether model is one of the tenant's self-hosted models. An empty name never
// matches: "free" is a claim that needs the model it is about.
func (d Deps) selfHostedModel(ctx context.Context, tenantID, model string) bool {
	model = strings.ToLower(strings.TrimSpace(model))
	if model == "" || d.Store == nil {
		return false
	}
	t, err := d.Store.GetTenant(ctx, tenantID)
	if err != nil {
		return false
	}
	return selfHostedModels(t)[model]
}

// spendFree reports whether a stored row is a self-hosted run, either flagged at write time or matched now.
func spendFree(e platform.AISpend, selfHosted map[string]bool) bool {
	return e.SelfHosted || selfHosted[strings.ToLower(strings.TrimSpace(e.Model))]
}
