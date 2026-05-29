package asset

import (
	"context"
	"testing"

	"github.com/ClatTribe/tsengine/internal/tool"
	"github.com/ClatTribe/tsengine/pkg/types"
)

type fakeTool struct{ name string }

func (f *fakeTool) Name() string                                      { return f.name }
func (*fakeTool) SandboxExecution() bool                              { return true }
func (*fakeTool) MITRETechniques() []string                           { return nil }
func (*fakeTool) Run(context.Context, tool.Args) (tool.Result, error) { return tool.Result{}, nil }

func resolver(names ...string) func(string) (tool.Tool, bool) {
	reg := map[string]tool.Tool{}
	for _, n := range names {
		reg[n] = &fakeTool{n}
	}
	return func(n string) (tool.Tool, bool) {
		t, ok := reg[n]
		return t, ok
	}
}

func TestEvalTriggers_FindingAndSurfaceMatch(t *testing.T) {
	triggers := []Trigger{
		{
			Name: "graphql→inql",
			Tool: "inql",
			MatchSurface: func(e string) (tool.Args, bool) {
				if e == "https://x/graphql" {
					return tool.Args{"target": e}, true
				}
				return nil, false
			},
		},
		{
			Name: "sqli-finding→deep",
			Tool: "deep",
			MatchFinding: func(f types.Finding) (tool.Args, bool) {
				for _, c := range f.CWE {
					if c == "CWE-89" {
						return tool.Args{"target": f.Endpoint}, true
					}
				}
				return nil, false
			},
		},
	}
	findings := []types.Finding{
		{RuleID: "nuclei::sqli", CWE: []string{"CWE-89"}, Endpoint: "https://x/p?id=1"},
		{RuleID: "nuclei::info", CWE: []string{"CWE-200"}, Endpoint: "https://x/i"},
	}
	surface := []string{"https://x/", "https://x/graphql"}

	out := EvalTriggers(triggers, surface, findings, resolver("inql", "deep"))
	if len(out) != 2 {
		t.Fatalf("got %d dispatches, want 2", len(out))
	}
	byTool := map[string]asset_dispatchInfo{}
	for _, d := range out {
		byTool[d.Tool.Name()] = asset_dispatchInfo{d.Args["target"].(string), d.EscalatedFrom}
	}
	if got := byTool["inql"]; got.target != "https://x/graphql" || got.from != "graphql→inql" {
		t.Errorf("inql dispatch = %+v", got)
	}
	if got := byTool["deep"]; got.target != "https://x/p?id=1" || got.from != "sqli-finding→deep" {
		t.Errorf("deep dispatch = %+v", got)
	}
}

type asset_dispatchInfo struct{ target, from string }

func TestEvalTriggers_DedupsByToolTarget(t *testing.T) {
	// Two findings on the SAME endpoint with the same trigger → one dispatch.
	tr := []Trigger{{
		Name: "dup",
		Tool: "deep",
		MatchFinding: func(f types.Finding) (tool.Args, bool) {
			return tool.Args{"target": f.Endpoint}, true
		},
	}}
	findings := []types.Finding{
		{RuleID: "a", Endpoint: "https://x/same"},
		{RuleID: "b", Endpoint: "https://x/same"},
		{RuleID: "c", Endpoint: "https://x/other"},
	}
	out := EvalTriggers(tr, nil, findings, resolver("deep"))
	if len(out) != 2 {
		t.Fatalf("got %d, want 2 (deduped by tool+target)", len(out))
	}
}

func TestEvalTriggers_SkipsUnregisteredTool(t *testing.T) {
	tr := []Trigger{{
		Name:         "x",
		Tool:         "not-installed",
		MatchFinding: func(types.Finding) (tool.Args, bool) { return tool.Args{"target": "t"}, true },
	}}
	out := EvalTriggers(tr, nil, []types.Finding{{RuleID: "a"}}, resolver())
	if len(out) != 0 {
		t.Errorf("unregistered tool should be skipped, got %d", len(out))
	}
}
