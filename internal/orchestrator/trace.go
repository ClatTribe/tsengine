package orchestrator

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sync"

	"github.com/ClatTribe/tsengine/internal/attest"
)

// trace.go is ADR 0032 D5: stage-level trace collection for a scan. Stages
// append records through the context (the same pattern as the failure sink);
// the caller drains them after RunWithSurface and writes the signed file via
// attest.SignTraceFile. Zero records = nothing to write; the trace never
// fabricates stages it did not observe.

type traceKey struct{}

// Trace collects one scan's stage records. Safe for concurrent Append — sweep
// and disprover run fan-out stages that report once per completion.
type Trace struct {
	mu      sync.Mutex
	records []attest.TraceRecord
}

// NewTrace returns a collector and a ctx carrying it.
func NewTrace(ctx context.Context) (context.Context, *Trace) {
	t := &Trace{}
	return context.WithValue(ctx, traceKey{}, t), t
}

// TraceFrom drains the collector attached by NewTrace. Nil when no collector is
// attached (plain context) — callers must treat nil as "no trace", never as an
// empty one.
func TraceFrom(ctx context.Context) *Trace {
	if t, ok := ctx.Value(traceKey{}).(*Trace); ok {
		return t
	}
	return nil
}

// Add appends one record. Model/token fields come from the executing brain when
// the seam reports usage; zeros mean unknown, and downstream rendering says so.
func (t *Trace) Add(stage, detail, model string, tokensIn, tokensOut int64, disposition string) {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	prev := ""
	if len(t.records) > 0 {
		prev = t.records[len(t.records)-1].Hash
	}
	rec := attest.TraceRecord{
		Stage: stage, Detail: detail, Model: model,
		TokensIn: tokensIn, TokensOut: tokensOut,
		Disposition: disposition, PrevHash: prev,
	}
	blob, _ := json.Marshal(rec)
	sum := sha256.Sum256(blob)
	rec.Hash = hex.EncodeToString(sum[:])
	t.records = append(t.records, rec)
}

// Records returns the collected records in append order.
func (t *Trace) Records() []attest.TraceRecord {
	if t == nil {
		return nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]attest.TraceRecord, len(t.records))
	copy(out, t.records)
	return out
}
