package l2

import (
	"context"
	"encoding/json"

	"github.com/ClatTribe/tsengine/pkg/types"
)

// readTools are the L2 read-state tools (crystal memory access). The Lead
// gets a compact digest of every L1 finding in the system prompt; when it
// needs the FULL detail of one (description, CWE, threat-intel, compliance,
// exploitability) it calls get_finding(id) rather than us inlining all of
// it — that's the §2.7-legit "reading state outside the conversation" tool
// and the thing that keeps the prompt small on a big scan.
func readTools(d Deps) Catalog {
	byID := make(map[string]types.Finding, len(d.L1Findings))
	for _, f := range d.L1Findings {
		byID[f.ID] = f
	}
	return Catalog{
		{
			Schema: ToolSchema{
				Name:        "get_finding",
				Description: "Fetch the FULL detail of one L1 finding by id (the prompt shows only a one-line digest). Use it before reporting/chaining so your analysis rests on the real evidence.",
				Params: obj(map[string]any{
					"id": str("the finding id, e.g. f-001"),
				}, "id"),
			},
			Handler: func(_ context.Context, args map[string]any, _ *State) (ToolResult, error) {
				id := argStr(args, "id")
				f, ok := byID[id]
				if !ok {
					return ToolResult{Err: true, Content: "no L1 finding with id " + id}, nil
				}
				return ToolResult{Content: renderFinding(f)}, nil
			},
		},
	}
}

// renderFinding returns the finding as compact JSON with raw_output elided
// (it can be huge; the agent rarely needs the tool's raw bytes, and the
// 2KB tool-result cap would truncate it anyway). All enrichment fields
// (cwe, threat_intel, compliance, exploitability, corroborated_by) survive.
func renderFinding(f types.Finding) string {
	f.RawOutput = nil
	b, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return "finding " + f.ID + " (render error)"
	}
	return string(b)
}
