package runner

import (
	"context"
	"errors"
	"fmt"
	"github.com/ClatTribe/tsengine/internal/tool"
	"log/slog"
	"strings"
	"time"

	"github.com/ClatTribe/tsengine/internal/asset"
	"github.com/ClatTribe/tsengine/internal/orchestrator"
	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// HandlerResolver maps an asset type to its engine Handler (cmd/tsengine's handlerFor,
// passed in so this package doesn't import every asset handler).
type HandlerResolver func(types.AssetType) (asset.Handler, error)

// EngineRunner is the real ScanRunner: it drives internal/orchestrator over a sandbox
// Dispatcher. It is the only place the platform touches the detection engine; the rest
// of the platform sees just the ScanRunner interface, so the engine stays unchanged
// and the glue stays testable with a fake.
//
// NewDispatcher spawns/owns a per-scan sandbox for the asset and returns the
// orchestrator.Dispatcher plus a cleanup func; the caller (cmd/platform) supplies it
// so sandbox lifecycle stays out of this package.
type EngineRunner struct {
	Resolve       HandlerResolver
	NewDispatcher func(ctx context.Context, a platform.Asset) (orchestrator.Dispatcher, func(), error)

	// NewDispatcherWithWorkspace, when set, SUPERSEDES NewDispatcher for scans and additionally
	// reports the host path holding this asset's source tree (empty for assets that have none).
	//
	// It is a second field rather than a changed signature because every existing caller — the
	// tests, and any future embedder — keeps working untouched. ADR 0029 D2a.
	NewDispatcherWithWorkspace func(ctx context.Context, a platform.Asset) (orchestrator.Dispatcher, string, func(), error)

	// Reachability, when set, annotates dependency findings with whether this repository's code can
	// actually reach them. It runs INSIDE the scan, while the workspace still exists — the platform
	// clones a repo for the duration of a scan and tears it down after, so there is no later moment
	// at which the tree is available.
	//
	// Nil, or a scan with no workspace, means no annotation. An absent verdict is not a claim; §10.
	Reachability func(root string, findings []types.Finding) []types.Finding
}

// dispatcherFor resolves the dispatcher and the scan's workspace path, preferring the
// workspace-aware factory when one is wired.
func (e *EngineRunner) dispatcherFor(ctx context.Context, a platform.Asset) (orchestrator.Dispatcher, string, func(), error) {
	if e.NewDispatcherWithWorkspace != nil {
		return e.NewDispatcherWithWorkspace(ctx, a)
	}
	disp, cleanup, err := e.NewDispatcher(ctx, a)
	return disp, "", cleanup, err
}

// Scan runs the engine over one asset and returns its grounded findings.
// Scan satisfies ScanRunner. It drops the execution report; callers that want it use ScanWithReport.
func (e *EngineRunner) Scan(ctx context.Context, a platform.Asset) ([]types.Finding, error) {
	f, _, err := e.ScanWithReport(ctx, a)
	return f, err
}

// ScanWithReport is Scan plus which tools actually dispatched and which failed, so the engagement
// record can distinguish a tool that ran clean from one that timed out or was missing from the image.
func (e *EngineRunner) ScanWithReport(ctx context.Context, a platform.Asset) ([]types.Finding, ScanReport, error) {
	at := types.AssetType(a.Type)
	handler, err := e.Resolve(at)
	if err != nil {
		return nil, ScanReport{}, fmt.Errorf("engine: resolve handler for %q: %w", a.Type, err)
	}
	disp, workspace, cleanup, err := e.dispatcherFor(ctx, a)
	if err != nil {
		return nil, ScanReport{}, fmt.Errorf("engine: dispatcher: %w", err)
	}
	if cleanup != nil {
		defer cleanup()
	}
	target := types.Asset{Type: at, Target: a.Target}
	findings, fired, _, toolsFailed, err := orchestrator.RunWithSurface(ctx, target, handler, disp)
	if err != nil {
		// fired = the tools the orchestrator dispatched. Logging it makes a 0-finding engine scan
		// diagnosable: no tools fired = a planning/dispatch gap; tools fired but 0 findings = a
		// sandbox tool-execution / propagation gap (vs the tools genuinely finding nothing).
		slog.Warn("[engine] scan errored", "type", a.Type, "target", a.Target, "fired", fired, "err", err.Error())
		return nil, ScanReport{}, fmt.Errorf("engine: scan %s: %w", a.Target, err)
	}
	// The code surface's validation rung, run here and nowhere else because here is the only place
	// the source tree exists: cleanup() is deferred above and destroys the clone on return.
	if e.Reachability != nil && workspace != "" {
		findings = e.Reachability(workspace, findings)
	}
	slog.Info("[engine] scan complete", "type", a.Type, "target", a.Target, "tools_fired", fired, "findings", len(findings))
	return findings, ScanReport{ToolsRan: fired, ToolsFailed: toolsFailed}, nil
}

// ReplayTool re-runs ONE tool against an asset with the security engineer's own arguments — the §9
// "dig deeper" capability, on the platform rather than only the engine CLI.
//
// This is the affordance that separates a tool a security engineer will trust from one they will
// not. The product decides which tools run and how; replay is where a human overrides that: run
// nuclei with my template, run sqlmap with a tamper script, prove or disprove the thing the agent
// claimed. Without it the engineer can only accept or reject what the AI chose to do, which is
// exactly the posture practitioners say they will not accept.
//
// It deliberately does NOT reuse internal/replay.Replay: that loads the original scan from a runs
// DIRECTORY to recover its pinned corpus, and the platform keeps scans in the store, not on disk.
// What is shared is the contract — a replay finding is stamped DiscoveryMethod{tool_replay, replayOf}
// so it is never mistaken for something a scheduled scan discovered.
func (e *EngineRunner) ReplayTool(ctx context.Context, a platform.Asset, toolName string, args tool.Args, replayID string) ([]types.Finding, error) {
	if strings.TrimSpace(toolName) == "" {
		return nil, errors.New("replay: no tool named")
	}
	disp, cleanup, err := e.NewDispatcher(ctx, a)
	if err != nil {
		return nil, fmt.Errorf("replay: dispatcher: %w", err)
	}
	if cleanup != nil {
		defer cleanup()
	}

	// The engineer's args win over the default target: overriding the target is a legitimate part of
	// digging deeper (§9 allows target override), and silently pinning it to the asset would make
	// half the tool's arguments inert without saying so.
	callArgs := tool.Args{"target": a.Target}
	for k, v := range args {
		callArgs[k] = v
	}

	res, err := disp.Execute(ctx, toolName, callArgs)
	if err != nil {
		return nil, fmt.Errorf("replay: execute %s: %w", toolName, err)
	}

	emitted := append([]types.SandboxEmittedFinding(nil), res.Findings...)
	emitted = append(emitted, res.SandboxEmittedFindings...)
	now := time.Now().UTC()
	out := make([]types.Finding, 0, len(emitted))
	for i, em := range emitted {
		out = append(out, types.Finding{
			ID:              fmt.Sprintf("%s-r%04d", replayID, i+1),
			RuleID:          em.RuleID,
			Tool:            em.Tool,
			Severity:        em.Severity,
			CWE:             em.CWE,
			Endpoint:        em.Endpoint,
			Title:           em.Title,
			Description:     em.Description,
			RawOutput:       em.RawOutput,
			MITRETechniques: em.MITRETechniques,
			ToolArgs:        em.ToolArgs,
			DiscoveredAt:    now,
			DiscoveryMethod: &types.DiscoveryMethod{Primary: "tool_replay", ReplayOf: replayID},
		})
	}
	return out, nil
}
