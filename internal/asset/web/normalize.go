package web

import (
	"fmt"
	"time"

	"github.com/ClatTribe/tsengine/internal/tool"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// normalize converts the per-tool ToolResults the orchestrator collected
// into canonical Findings. Tool wrappers already produce
// SandboxEmittedFinding via their parsers; this step lifts those into
// Finding shape, assigns sequential IDs, and stamps a DiscoveredAt.
//
// The host-side L1.5 hook chain (Phase 4) runs AFTER this step on the
// emitted Findings — Normalize itself just shapes the data.
func normalize(results []tool.Result) []types.Finding {
	now := time.Now().UTC()
	out := make([]types.Finding, 0)
	idx := 0
	for _, r := range results {
		for _, e := range allEmitted(r) {
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

// allEmitted returns the union of Result.Findings + Result.SandboxEmittedFindings,
// which is how individual wrappers signal output. Wrappers that explicitly
// return findings via Result.Findings (nuclei, dalfox) are the common case;
// the sidecar channel is used by tools that internally called the sandbox
// tracer (Phase 1's bridge pattern, CLAUDE.md §12.4).
func allEmitted(r tool.Result) []types.SandboxEmittedFinding {
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
