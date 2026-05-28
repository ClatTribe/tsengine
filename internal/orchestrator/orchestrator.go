// Package orchestrator runs the per-asset L1 anchor sequence: it asks
// the asset Handler for its anchors, applies the asset filter, executes
// surviving dispatches in the sandbox with bounded concurrency, and
// normalizes the per-tool results into canonical Findings.
//
// The host-side L1.5 hook chain (Phase 4) runs AFTER orchestrator
// returns — the L1 layer that webappsec's security-engineer audience
// reads is what the orchestrator emits. CLAUDE.md §1.5.1, §11.
package orchestrator

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"sync"

	"golang.org/x/sync/errgroup"

	"github.com/ClatTribe/tsengine/internal/asset"
	"github.com/ClatTribe/tsengine/internal/tool"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// Dispatcher executes a single (tool, args) pair. Production: sandbox.Client.
// Tests pass in mocks.
type Dispatcher interface {
	Execute(ctx context.Context, toolName string, args tool.Args) (tool.Result, error)
}

// Run executes the L1 anchor prepass for one asset target.
//
// Steps:
//
//  1. Build a Dispatch per anchor tool, each carrying args["target"] =
//     target.Target (Phase 2 has no recon stage yet — recon-derived URL
//     fan-out arrives with the katana wrapper).
//  2. Pass the dispatch set through Handler.Filter() — Q5.34 style
//     filtration shrinks it.
//  3. Execute remaining dispatches concurrently via dispatcher, with
//     concurrency bounded by TSENGINE_DISPATCH_CONCURRENCY (default 4).
//  4. Call Handler.Normalize() to lift per-tool ToolResults into
//     canonical Findings.
//
// Returns the normalized findings + the list of anchor tool names that
// actually executed (anchors_fired in vulnerabilities.json).
func Run(ctx context.Context, target types.Asset, handler asset.Handler, dispatcher Dispatcher) ([]types.Finding, []string, error) {
	if handler == nil {
		return nil, nil, errors.New("orchestrator: nil handler")
	}
	if dispatcher == nil {
		return nil, nil, errors.New("orchestrator: nil dispatcher")
	}

	dispatches := handler.PlanAnchors(target)
	dispatches = handler.Filter(ctx, target, dispatches)

	results, fired, err := executeAll(ctx, dispatches, dispatcher)
	if err != nil {
		return nil, fired, err
	}
	findings := handler.Normalize(results)
	return findings, fired, nil
}

// executeAll runs dispatches concurrently with a bounded semaphore.
// Returns ordered results (by anchor list position) so vulnerabilities.json
// has deterministic ordering for reproducibility.
func executeAll(ctx context.Context, dispatches []asset.Dispatch, dispatcher Dispatcher) ([]tool.Result, []string, error) {
	conc := concurrencyLimit()
	results := make([]tool.Result, len(dispatches))
	fired := make([]string, len(dispatches))

	g, gctx := errgroup.WithContext(ctx)
	sem := make(chan struct{}, conc)
	var failed sync.Map // index -> error (best-effort logging)

	for i, d := range dispatches {
		i, d := i, d
		g.Go(func() error {
			select {
			case sem <- struct{}{}:
			case <-gctx.Done():
				return gctx.Err()
			}
			defer func() { <-sem }()

			res, err := dispatcher.Execute(gctx, d.Tool.Name(), d.Args)
			if err != nil {
				// A single tool failure should not abort the scan. The
				// security-engineer audience can see partial output —
				// arch.md "the per-tool dashboard is best-effort and
				// reports what each tool produced".
				failed.Store(i, err)
				return nil
			}
			results[i] = res
			fired[i] = d.Tool.Name()
			return nil
		})
	}
	if err := g.Wait(); err != nil {
		return nil, nil, err
	}

	// Drop slots from failed tools so anchors_fired only lists tools
	// that actually produced results.
	cleanResults := make([]tool.Result, 0, len(results))
	cleanFired := make([]string, 0, len(fired))
	for i := range results {
		if fired[i] == "" {
			continue
		}
		cleanResults = append(cleanResults, results[i])
		cleanFired = append(cleanFired, fired[i])
	}
	return cleanResults, cleanFired, nil
}

// concurrencyLimit honors TSENGINE_DISPATCH_CONCURRENCY; default 4 per
// CLAUDE.md §15. Returns at least 1.
func concurrencyLimit() int {
	if v := os.Getenv("TSENGINE_DISPATCH_CONCURRENCY"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return 4
}

// ErrToolFailed wraps a tool execution failure so the orchestrator can
// communicate it without aborting the scan. Currently unused externally
// — kept for the Phase 4 introspection layer.
var ErrToolFailed = fmt.Errorf("tool failed")
