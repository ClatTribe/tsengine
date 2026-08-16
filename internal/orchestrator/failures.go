package orchestrator

import (
	"context"
	"sync"

	"github.com/ClatTribe/tsengine/pkg/types"
)

// Tool failures were surfaced to STDERR only. The comment at the print site already named the
// problem — "a tool that ERRORED looked identical to a tool that found nothing" — but the fix stopped
// at the operator's terminal and never reached vulnerabilities.json, the §6 dashboard contract every
// downstream consumer actually reads.
//
// Measured cost of that gap: four runs of the SAME command against the SAME unchanged API returned
// 1, 1, 11 and 11 findings, with three different toolsets, and `partial=false` every time. The two
// one-finding runs were simply under machine load, so tools lost their per-tool timeout race and
// were dropped from anchors_fired. A 91% recall collapse was indistinguishable, in the artifact,
// from a clean scan.
//
// A collector on the context rather than an extra parameter: the failure data is cross-cutting and
// the call chain (RunWithSurface → executeWaves → executeAll) has six internal call sites plus test
// callers, none of which have any business knowing about it.

type failureSink struct {
	mu   sync.Mutex
	list []types.ToolFailure
}

func (s *failureSink) add(tool, reason string) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.list = append(s.list, types.ToolFailure{Tool: tool, Reason: reason})
}

func (s *failureSink) snapshot() []types.ToolFailure {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]types.ToolFailure(nil), s.list...)
}

type failureCtxKey struct{}

// withFailureSink attaches a collector so nested dispatch stages can record tool failures.
func withFailureSink(ctx context.Context, s *failureSink) context.Context {
	return context.WithValue(ctx, failureCtxKey{}, s)
}

// failureSinkFrom returns the collector, or nil when none is attached — a nil sink silently discards,
// so callers that never opted in (tests, internal.Run) behave exactly as before.
func failureSinkFrom(ctx context.Context) *failureSink {
	s, _ := ctx.Value(failureCtxKey{}).(*failureSink)
	return s
}
