package cloudengine

import "sync/atomic"

// usage.go is the token/cost accounting seam for every agent that drives an LLM (ADR 0030
// Phase D — "$/finding recorded beside rates"). Before this, ALL THREE clients parsed and
// DISCARDED their responses' usage blocks, so no offensive run could state what it cost — and a
// fleet-vs-single ablation that cannot see cost cannot judge a trade-off.
//
// Design: the interface stays `Generate(ctx, prompt) (string, error)` — changing the core
// signature would ripple through every fake/mock in the tree for a nice-to-have. Instead each
// client accumulates its usage CUMULATIVELY in atomics and exposes it via TotalUsage(); an
// engagement captures a baseline before its loop and reads the delta after. Concurrent workers
// sharing one client still yield an EXACT engagement total (the counter is shared), though
// per-worker attribution is approximate — stated where it is reported.

// Usage is one accounting snapshot: raw token counts from the provider.
type Usage struct {
	InputTokens     int64 `json:"input_tokens"`
	OutputTokens    int64 `json:"output_tokens"`
	CacheReadTokens int64 `json:"cache_read_tokens,omitempty"` // prompt tokens served from cache (billed ~10%)
}

// Total returns in+out (cache reads are already part of input).
func (u Usage) Total() int64 { return u.InputTokens + u.OutputTokens }

// UsageReporter is implemented by clients that account usage. Zero-value safe to type-assert:
// agents MUST treat absence as "cost unknown", never as zero cost (§10 — unknown ≠ free).
type UsageReporter interface {
	TotalUsage() Usage
}

// ModelNamer is implemented by clients that know their model id (needed to price usage).
type ModelNamer interface {
	ModelName() string
}

// usageCounter is the atomic accumulator embedded in each client.
type usageCounter struct {
	in, out, cache atomic.Int64
}

func (c *usageCounter) add(u Usage) {
	c.in.Add(u.InputTokens)
	c.out.Add(u.OutputTokens)
	c.cache.Add(u.CacheReadTokens)
}

func (c *usageCounter) total() Usage {
	return Usage{InputTokens: c.in.Load(), OutputTokens: c.out.Load(), CacheReadTokens: c.cache.Load()}
}

// price is $/1M tokens {input, output} — ONE table shared by every agent seam. The numbers are
// the ones internal/l2's verifier has priced all along; l2's estimateCost delegates here so two
// tables can never drift apart.
type price struct{ in, out float64 }

var pricing = map[string]price{
	"gemini-2.5-pro":    {1.25, 10.0},
	"gemini-2.5-flash":  {0.30, 2.50},
	"gpt-4o":            {2.50, 10.0},
	"gpt-4o-mini":       {0.15, 0.60},
	"claude-sonnet-4-5": {3.0, 15.0},
	"claude-opus-4-1":   {15.0, 75.0},
	"claude-haiku-4-5":  {1.0, 5.0},
}

// EstimateCost prices a usage snapshot by model id. An unknown model uses a sensible mid-range
// default rather than zero — pricing an unknown model at $0 would understate every local-proxy
// run's true spend; overstating slightly is the honest direction.
func EstimateCost(model string, u Usage) float64 {
	p, ok := pricing[model]
	if !ok {
		p = price{3.0, 15.0}
	}
	const m = 1_000_000.0
	fresh := u.InputTokens - u.CacheReadTokens
	if fresh < 0 {
		fresh = u.InputTokens
	}
	return (float64(fresh)*p.in +
		float64(u.CacheReadTokens)*p.in*0.1 +
		float64(u.OutputTokens)*p.out) / m
}
