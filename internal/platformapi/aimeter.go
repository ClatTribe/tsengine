package platformapi

import (
	"context"
	"sync"
	"time"

	"github.com/ClatTribe/tsengine/internal/cloudengine"
	"github.com/ClatTribe/tsengine/internal/pentest"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

// aimeter.go: every model call a tenant's work makes is recorded, not only the runs someone remembered
// to meter.
//
// THE GAP. AISpend rows were written by the paths that called recordAISpend by hand — the Lead, and the
// cloud and code specialists. Every other caller of resolveAgentLLMForRole (exploit proposals, the code
// sweep, CWE attribution, eval scoring, autofix, the compliance advisor, …) spent model money that the
// monthly ceiling never saw, so a customer's budget could be "not yet reached" while it was being
// exceeded. The fix is at the one door every one of them already goes through.
//
// TWO RULES the wrapper keeps:
//
//  1. Usage is read from a client nobody else is using. The cumulative counter on a SHARED operator
//     client mixes every tenant's concurrent calls, so a delta across one run can contain another
//     tenant's tokens. Deps.AgentLLMFactory builds a fresh operator client per resolve, and a tenant's
//     own client is already built per resolve.
//
//  2. A run that records its own row is not counted twice. The cloud and code specialists price a whole
//     run and attach what it proved; they mark their context with meteredRun and the wrapper records
//     nothing inside it (it still advances its counter, so the next call outside the run is not billed
//     for the run's tokens).
//
// Unknown stays unknown: a client that reports no usage produces a row with CostKnown=false, never $0.

type runMeteredKey struct{}

// meteredRun marks ctx as a run that records its own spend row.
func meteredRun(ctx context.Context) context.Context {
	return context.WithValue(ctx, runMeteredKey{}, true)
}

type aiKindKey struct{}

type aiKindLabel struct{ kind, surface string }

// aiKind labels the calls made under ctx for the spend record. Optional: an unlabelled call is still
// recorded, as "model call" on surface "other" — labelling is for the value view, metering is not.
func aiKind(ctx context.Context, kind, surface string) context.Context {
	return context.WithValue(ctx, aiKindKey{}, aiKindLabel{kind: kind, surface: surface})
}

type spendMeter struct {
	inner    pentest.SpecLLM
	d        Deps
	tenantID string
	label    aiKindLabel // from the ctx the client was resolved under; a Generate ctx label overrides it

	mu   sync.Mutex
	last cloudengine.Usage
}

// meter wraps a resolved client. A nil client stays nil, so callers' nil checks keep meaning "no model".
func (d Deps) meter(ctx context.Context, inner pentest.SpecLLM, tenantID string) pentest.SpecLLM {
	if inner == nil {
		return nil
	}
	m := &spendMeter{inner: inner, d: d, tenantID: tenantID}
	m.label, _ = ctx.Value(aiKindKey{}).(aiKindLabel)
	if ur, ok := inner.(cloudengine.UsageReporter); ok {
		m.last = ur.TotalUsage()
	}
	return m
}

func (m *spendMeter) Generate(ctx context.Context, prompt string) (string, error) {
	out, err := m.inner.Generate(ctx, prompt)
	m.record(ctx)
	return out, err
}

// record bills the usage accrued since the last record. Under concurrent calls on one client each
// delta may include a sibling's tokens, but every token is billed exactly once and all of them belong
// to the same tenant — the sum is exact even where the split between two parallel calls is not.
func (m *spendMeter) record(ctx context.Context) {
	var delta cloudengine.Usage
	if ur, ok := m.inner.(cloudengine.UsageReporter); ok {
		m.mu.Lock()
		total := ur.TotalUsage()
		delta = cloudengine.Usage{
			InputTokens:     total.InputTokens - m.last.InputTokens,
			OutputTokens:    total.OutputTokens - m.last.OutputTokens,
			CacheReadTokens: total.CacheReadTokens - m.last.CacheReadTokens,
		}
		m.last = total
		m.mu.Unlock()
	}
	if v, _ := ctx.Value(runMeteredKey{}).(bool); v {
		return
	}
	label, _ := ctx.Value(aiKindKey{}).(aiKindLabel)
	if label.kind == "" {
		label = m.label
	}
	if label.kind == "" {
		label = aiKindLabel{kind: "model call", surface: "other"}
	}
	e := platform.AISpend{
		ID: spendID(), TenantID: m.tenantID, At: time.Now().UTC(), Kind: label.kind, Surface: label.surface,
		Model: m.ModelName(), PerCall: true,
	}
	if delta.Total() > 0 {
		e.USD, e.CostKnown = cloudengine.EstimateCost(e.Model, delta), true
	}
	m.d.putSpend(context.WithoutCancel(ctx), e)
}

// TotalUsage forwards, so a run that prices itself (usageMeter) still can.
func (m *spendMeter) TotalUsage() cloudengine.Usage {
	if ur, ok := m.inner.(cloudengine.UsageReporter); ok {
		return ur.TotalUsage()
	}
	return cloudengine.Usage{}
}

func (m *spendMeter) ModelName() string {
	if mn, ok := m.inner.(cloudengine.ModelNamer); ok {
		return mn.ModelName()
	}
	return ""
}
