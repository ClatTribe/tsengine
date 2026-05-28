// Package tool defines the Tool interface every OSS wrapper implements,
// and the global registry the orchestrator + sandbox tool-server both
// look up by name. See CLAUDE.md §12.3.
package tool

import (
	"context"

	"github.com/ClatTribe/tsengine/pkg/types"
)

// Tool wraps a single OSS scanner or framework primitive. One Tool impl
// per OSS tool. Implementations register themselves via Register() from
// their package init() so cmd/tsengine and cmd/tool-server share a
// single source of truth at startup.
type Tool interface {
	// Name is the stable identifier for this tool. Used for dispatch,
	// catalog membership, and finding attribution (Finding.Tool). Must
	// be unique across all registered tools.
	Name() string

	// SandboxExecution reports whether this tool must dispatch into the
	// sandbox container. Default for any new wrapper is true; opt out
	// only for host-only framework state-management tools (workflow,
	// tracer, finish_scan).
	SandboxExecution() bool

	// MITRETechniques returns the MITRE ATT&CK technique IDs this tool's
	// findings are attributed to. Surfaced in the L1 dashboard.
	MITRETechniques() []string

	// Run executes the tool. On the host this is invoked via the
	// sandbox HTTP client; on the sandbox side it's invoked by the
	// tool-server directly. Implementations MUST honor ctx.Done().
	Run(ctx context.Context, args Args) (Result, error)
}

// Args is the per-call argument bag. Wrapped tools project these into
// CLI flags / library options.
type Args map[string]any

// Result is the wire format every tool returns. Findings are the
// host-shape findings the tool emits explicitly; SandboxEmittedFindings
// is the sidecar channel populated by the tool-server when the tool
// internally called the sandbox-side tracer (CLAUDE.md §12.4).
//
// Output is opaque tool-specific payload preserved for the security
// engineer audience — written into Finding.RawOutput by the host
// normalization step.
type Result struct {
	Output                 any                           `json:"output,omitempty"`
	Findings               []types.SandboxEmittedFinding `json:"findings,omitempty"`
	SandboxEmittedFindings []types.SandboxEmittedFinding `json:"_sandbox_emitted_findings,omitempty"`
}
