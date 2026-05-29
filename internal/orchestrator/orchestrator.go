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
	"strings"
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

	// Recon-capable assets (web crawl, api spec ingest) run a two-stage
	// flow: discover the surface, then fan detection tools across it.
	// Assets without a recon stage fall through to single-target
	// PlanAnchors. The recon stage is deterministic — not prompt-driven —
	// so tsengine never hits strix's "model ignored the recon directive"
	// class of bug (CLAUDE.md §10).
	if rh, ok := handler.(asset.ReconHandler); ok && len(rh.Recon()) > 0 {
		return runWithRecon(ctx, target, handler, rh, dispatcher)
	}

	dispatches := handler.PlanAnchors(target)
	dispatches = handler.Filter(ctx, target, dispatches)

	results, fired, err := executeWaves(ctx, dispatches, dispatcher)
	if err != nil {
		return nil, fired, err
	}
	findings := handler.Normalize(results)
	return findings, fired, nil
}

// runWithRecon implements the two-stage recon → fan-out flow:
//
//  1. Run the recon tools (katana) → collect Result.DiscoveredURLs into
//     the scan surface (capped + deduped; the original target is always
//     included so a crawl that finds nothing still scans the target).
//  2. PlanFanout shapes the (tool × URL) detection dispatches; Filter
//     prunes them (scope, static-asset, login-protection, per-URL
//     routing); executeAll runs them concurrently.
//
// Recon findings (if any) + fan-out findings are both normalized, so a
// recon tool that also emits a finding never loses it.
func runWithRecon(ctx context.Context, target types.Asset, handler asset.Handler, rh asset.ReconHandler, dispatcher Dispatcher) ([]types.Finding, []string, error) {
	reconDispatches := asset.DefaultPlanAnchors(target, rh.Recon())
	reconResults, reconFired, err := executeAll(ctx, reconDispatches, dispatcher)
	if err != nil {
		return nil, reconFired, err
	}

	surface := asset.CollectSurface(target.Target, reconResults, fanoutMaxURLs())
	fmt.Fprintf(os.Stderr, "[recon] %s discovered surface=%d URLs (cap %d)\n",
		strings.Join(reconFired, ","), len(surface), fanoutMaxURLs())

	dispatches := rh.PlanFanout(target, surface)
	dispatches = handler.Filter(ctx, target, dispatches)

	fanoutResults, fanoutFired, err := executeWaves(ctx, dispatches, dispatcher)
	if err != nil {
		return nil, append(reconFired, fanoutFired...), err
	}

	allResults := append(reconResults, fanoutResults...)
	findings := handler.Normalize(allResults)
	return findings, append(reconFired, fanoutFired...), nil
}

// fanoutMaxURLs caps the discovered surface to bound fan-out cost.
// strix's unbounded WAVSEP fan-out ran for hours (Q5.34l); the cap is
// the guard. Honors TSENGINE_FANOUT_MAX_URLS (default 200).
func fanoutMaxURLs() int {
	if v := os.Getenv("TSENGINE_FANOUT_MAX_URLS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return 200
}

// executeWaves runs dispatches in dependency-ordered waves: concurrent
// within a wave (executeAll), sequential across waves. An all-independent
// batch collapses to one wave — the common case, zero overhead. This is
// the safety guard that lets the fan-out stay parallel without racing a
// state-writer against its reader once auth/verify tools land (see deps.go).
func executeWaves(ctx context.Context, dispatches []asset.Dispatch, dispatcher Dispatcher) ([]tool.Result, []string, error) {
	waves := partitionWaves(dispatches)
	if len(waves) <= 1 {
		return executeAll(ctx, dispatches, dispatcher)
	}
	var allResults []tool.Result
	var allFired []string
	var session string // captured by seed_auth in an earlier wave
	for _, wave := range waves {
		// Thread a session captured by an earlier wave into this wave's
		// authed dispatches (seed_auth → authed re-scan). Don't clobber a
		// per-dispatch cookie if one was set explicitly.
		if session != "" {
			for i := range wave {
				if wave[i].Args == nil {
					wave[i].Args = tool.Args{}
				}
				if _, has := wave[i].Args["cookie"]; !has {
					wave[i].Args["cookie"] = session
				}
			}
		}
		r, f, err := executeAll(ctx, wave, dispatcher)
		if err != nil {
			return nil, allFired, err
		}
		for _, res := range r {
			if res.CapturedSession != "" {
				session = res.CapturedSession
			}
		}
		allResults = append(allResults, r...)
		allFired = append(allFired, f...)
	}
	return allResults, allFired, nil
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
