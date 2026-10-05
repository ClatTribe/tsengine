package platformapi

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"log/slog"
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
