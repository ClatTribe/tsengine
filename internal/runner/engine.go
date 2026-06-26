package runner

import (
	"context"
	"fmt"
	"log/slog"

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
}

// Scan runs the engine over one asset and returns its grounded findings.
func (e *EngineRunner) Scan(ctx context.Context, a platform.Asset) ([]types.Finding, error) {
	at := types.AssetType(a.Type)
	handler, err := e.Resolve(at)
	if err != nil {
		return nil, fmt.Errorf("engine: resolve handler for %q: %w", a.Type, err)
	}
	disp, cleanup, err := e.NewDispatcher(ctx, a)
	if err != nil {
		return nil, fmt.Errorf("engine: dispatcher: %w", err)
	}
	if cleanup != nil {
		defer cleanup()
	}
	target := types.Asset{Type: at, Target: a.Target}
	findings, fired, err := orchestrator.Run(ctx, target, handler, disp)
	if err != nil {
		// fired = the tools the orchestrator dispatched. Logging it makes a 0-finding engine scan
		// diagnosable: no tools fired = a planning/dispatch gap; tools fired but 0 findings = a
		// sandbox tool-execution / propagation gap (vs the tools genuinely finding nothing).
		slog.Warn("[engine] scan errored", "type", a.Type, "target", a.Target, "fired", fired, "err", err.Error())
		return nil, fmt.Errorf("engine: scan %s: %w", a.Target, err)
	}
	slog.Info("[engine] scan complete", "type", a.Type, "target", a.Target, "tools_fired", fired, "findings", len(findings))
	return findings, nil
}
