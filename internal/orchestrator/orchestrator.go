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
	"time"

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
	// Even on a deadline error we normalize + return the partial results so
	// the CLI can persist them (err signals "partial", findings are kept).
	// Single-stage assets have no recon surface; the target itself is it.
	findings, allFired := finalizeWithEscalation(ctx, target, handler, dispatcher, results, fired, []string{target.Target})
	return findings, allFired, err
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
	// A ReconPlanner shapes its own recon dispatches (crawl depth, seeds);
	// otherwise fall back to the generic single-arg target mapping.
	var reconDispatches []asset.Dispatch
	if rp, ok := handler.(asset.ReconPlanner); ok {
		reconDispatches = rp.PlanRecon(target)
	} else {
		reconDispatches = asset.DefaultPlanAnchors(target, rh.Recon())
	}
	reconResults, reconFired, err := executeAll(ctx, reconDispatches, dispatcher)
	if err != nil {
		// Recon itself was cut short — normalize + return whatever it
		// produced (usually empty) so the caller persists it.
		findings, f := finalizeWithEscalation(ctx, target, handler, dispatcher, reconResults, reconFired, []string{target.Target})
		return findings, f, err
	}

	// ResolveSurface filters + prioritizes BEFORE capping (web), so the cap
	// budget holds real, distinct, high-value endpoints — not the first N
	// raw crawl hits. Assets without a SurfaceSelector get plain dedupe+cap.
	surface := asset.ResolveSurface(handler, target, reconResults, fanoutMaxURLs())
	fmt.Fprintf(os.Stderr, "[recon] %s discovered surface=%d URLs (cap %d, filtered+prioritized)\n",
		strings.Join(reconFired, ","), len(surface), fanoutMaxURLs())

	dispatches := rh.PlanFanout(target, surface)
	dispatches = handler.Filter(ctx, target, dispatches)

	// fanoutErr is non-nil only on a deadline; fanoutResults still holds
	// every detector that completed before it (the WAVSEP timeout case —
	// keep the partial findings rather than scoring zero).
	fanoutResults, fanoutFired, fanoutErr := executeWaves(ctx, dispatches, dispatcher)

	allResults := append(reconResults, fanoutResults...)
	allFired := append(reconFired, fanoutFired...)
	findings, fnFired := finalizeWithEscalation(ctx, target, handler, dispatcher, allResults, allFired, surface)
	return findings, fnFired, fanoutErr
}

// finalizeWithEscalation is the shared tail of both the single-stage and
// recon paths: it runs the deterministic escalation stage (if the Handler
// implements asset.EscalationPlanner), then normalizes detection +
// escalation results together.
//
// Escalation = conditional depth: the handler inspects the detection
// findings + surface and proposes DEEP tool dispatches only where a signal
// warrants (a /graphql endpoint → inql, a login → hydra, …). Bounded by
// TSENGINE_ESCALATION_MAX so a flood of signals can't explode cost, and by
// the per-tool timeout (C3). This is the L1 (reproducible) half of "which
// tool when"; the open-ended half is L2 (Phase 6). CLAUDE.md §5.3.
func finalizeWithEscalation(ctx context.Context, target types.Asset, handler asset.Handler, dispatcher Dispatcher, detResults []tool.Result, detFired []string, surface []string) ([]types.Finding, []string) {
	allResults := detResults
	allFired := detFired

	// Skip escalation if the scan was already cut short (deadline) — no
	// point dispatching depth tools onto a dead context; we just normalize
	// the partial detection results so they're persisted.
	if ctx.Err() == nil {
		if ep, ok := handler.(asset.EscalationPlanner); ok {
			// Trigger evaluation needs findings, so normalize the detection
			// results to an interim view (IDs here are throwaway; the final
			// Normalize over all results assigns the canonical IDs).
			interim := handler.Normalize(detResults)
			esc := ep.PlanEscalation(target, surface, interim)
			esc = capEscalation(esc)
			esc = handler.Filter(ctx, target, esc)
			if len(esc) > 0 {
				labels := make([]string, 0, len(esc))
				for _, d := range esc {
					labels = append(labels, d.EscalatedFrom)
				}
				fmt.Fprintf(os.Stderr, "[escalate] %d depth dispatch(es): %s\n",
					len(esc), strings.Join(labels, ","))
				// Best-effort: a deadline mid-escalation keeps the partial
				// escalation results too.
				r, f, _ := executeWaves(ctx, esc, dispatcher)
				allResults = append(allResults, r...)
				allFired = append(allFired, f...)
			}
		}
	}

	findings := handler.Normalize(allResults)
	return findings, allFired
}

// capEscalation bounds the escalation dispatch set to TSENGINE_ESCALATION_MAX
// (default 50). The guard against a signal flood turning "in-depth" into
// "unbounded" — the cost twin of TSENGINE_FANOUT_MAX_URLS.
func capEscalation(in []asset.Dispatch) []asset.Dispatch {
	max := 50
	if v := os.Getenv("TSENGINE_ESCALATION_MAX"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			max = n
		}
	}
	if len(in) > max {
		return in[:max]
	}
	return in
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
		// Accumulate the partial set BEFORE the error check so a mid-wave
		// cancellation keeps every result that completed (incl. earlier
		// whole waves).
		for _, res := range r {
			if res.CapturedSession != "" {
				session = res.CapturedSession
			}
		}
		allResults = append(allResults, r...)
		allFired = append(allFired, f...)
		if err != nil {
			return allResults, allFired, err
		}
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

			// Optional per-tool timeout. The parent ctx (scan --timeout) is
			// the single source of truth — there is NO fixed host client
			// timeout, and the tool-server runs each tool on the request
			// ctx, so host cancellation propagates into the sandbox via
			// connection close. tsengine therefore can't hit strix's
			// "timeout split-brain" (host 120s < sandbox 300s) by
			// construction. This per-tool cap is a separate, opt-in safety
			// valve: it stops ONE runaway tool (e.g. sqlmap grinding a
			// single hard URL) from consuming the whole scan budget and
			// starving its siblings. Default 0 = no per-tool cap.
			ectx := gctx
			// The per-tool cap targets ONE runaway single-target tool (e.g.
			// sqlmap grinding a hard URL). It must NOT apply to a LIST-mode
			// dispatch (args["targets"] = many URLs): that's a batch job —
			// nuclei fuzzing ~hundreds of URLs in one engine — governed by its
			// own per-request timeout + the scan --timeout. Capping the whole
			// batch at the single-tool budget truncates it mid-list (the
			// nuclei -dast list would die after ~startup, scanning almost
			// nothing).
			_, isListMode := d.Args["targets"]
			if tt := toolTimeout(); tt > 0 && !isListMode {
				var cancel context.CancelFunc
				ectx, cancel = context.WithTimeout(gctx, tt)
				defer cancel()
			}

			res, err := dispatcher.Execute(ectx, d.Tool.Name(), d.Args)
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
	// waitErr is non-nil only on ctx cancellation (the scan --timeout) — a
	// queued goroutine returns gctx.Err(); per-tool failures are swallowed
	// above. We do NOT discard the partial set on cancellation: tools that
	// completed before the deadline wrote their slots, and the caller
	// persists them (the no-score-on-timeout trap, see CLAUDE.md §5.1).
	waitErr := g.Wait()
	// Robust partial-flag: if every in-flight tool happened to swallow the
	// deadline (no goroutine was queued to surface gctx.Err — possible when
	// dispatches ≤ concurrency), still report the cancellation so the caller
	// marks the scan partial.
	if waitErr == nil && ctx.Err() != nil {
		waitErr = ctx.Err()
	}

	// Surface swallowed tool failures (per-tool timeouts + real errors). These
	// were invisible before — a tool that ERRORED looked identical to a tool
	// that found nothing, which masks detection bugs (e.g. is sqlmap timing
	// out, or is it running clean and finding nothing?).
	nFail := 0
	failed.Range(func(k, v any) bool {
		nFail++
		if nFail <= 8 {
			fmt.Fprintf(os.Stderr, "[dispatch] %s failed: %v\n", dispatches[k.(int)].Tool.Name(), v)
		}
		return true
	})
	if nFail > 8 {
		fmt.Fprintf(os.Stderr, "[dispatch] +%d more tool failure(s)\n", nFail-8)
	}

	// Drop slots from failed/cancelled tools so anchors_fired only lists
	// tools that actually produced results.
	cleanResults := make([]tool.Result, 0, len(results))
	cleanFired := make([]string, 0, len(fired))
	for i := range results {
		if fired[i] == "" {
			continue
		}
		cleanResults = append(cleanResults, results[i])
		cleanFired = append(cleanFired, fired[i])
	}
	return cleanResults, cleanFired, waitErr
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

// toolTimeout honors TSENGINE_TOOL_TIMEOUT (a Go duration, e.g. "90s",
// "5m"), the OPT-IN per-tool wall-clock cap. Default 0 = no cap (the scan
// --timeout governs). A bad/zero value disables the cap. This is the knob
// that makes a per-URL injection fan-out (sqlmap across a large surface)
// bounded: each tool gets at most this long before it's cancelled and the
// scan moves on with partial results.
func toolTimeout() time.Duration {
	if v := os.Getenv("TSENGINE_TOOL_TIMEOUT"); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			return d
		}
	}
	return 0
}

// ErrToolFailed wraps a tool execution failure so the orchestrator can
// communicate it without aborting the scan. Currently unused externally
// — kept for the Phase 4 introspection layer.
var ErrToolFailed = fmt.Errorf("tool failed")
