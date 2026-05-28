// Package common holds normalize helpers shared across asset modules.
// Each asset's Handler.Normalize lifts SandboxEmittedFindings into
// canonical Findings the same way — finding-ID assignment, timestamp,
// projection of all annotation slots through. Centralizing that
// keeps the 7 Handlers small.
package common

import (
	"fmt"
	"time"

	"github.com/ClatTribe/tsengine/internal/tool"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// Normalize converts the per-tool ToolResults the orchestrator collected
// into canonical Findings. Findings are flattened across all results
// with sequential IDs (f-0001, f-0002, ...). The host-side L1.5 hook
// chain runs AFTER this step (Phase 4) — Normalize itself just shapes
// data.
func Normalize(results []tool.Result) []types.Finding {
	now := time.Now().UTC()
	out := make([]types.Finding, 0)
	idx := 0
	for _, r := range results {
		for _, e := range emitted(r) {
			idx++
			out = append(out, types.Finding{
				ID:              fmt.Sprintf("f-%04d", idx),
				RuleID:          e.RuleID,
				Tool:            e.Tool,
				Severity:        e.Severity,
				CWE:             e.CWE,
				Endpoint:        e.Endpoint,
				Title:           e.Title,
				Description:     e.Description,
				RawOutput:       e.RawOutput,
				MITRETechniques: e.MITRETechniques,
				ToolArgs:        e.ToolArgs,
				DiscoveredAt:    now,
			})
		}
	}
	return out
}

// emitted is the union of Result.Findings + Result.SandboxEmittedFindings.
// The sidecar channel is used by tools that internally called the
// sandbox tracer (CLAUDE.md §12.4 bridge); the explicit Findings field
// is used by wrappers that just return findings directly.
func emitted(r tool.Result) []types.SandboxEmittedFinding {
	if len(r.SandboxEmittedFindings) == 0 {
		return r.Findings
	}
	if len(r.Findings) == 0 {
		return r.SandboxEmittedFindings
	}
	out := make([]types.SandboxEmittedFinding, 0, len(r.Findings)+len(r.SandboxEmittedFindings))
	out = append(out, r.Findings...)
	out = append(out, r.SandboxEmittedFindings...)
	return out
}
