package web

import (
	"context"
	"testing"

	"github.com/ClatTribe/tsengine/internal/asset"
	"github.com/ClatTribe/tsengine/internal/tool"
	"github.com/ClatTribe/tsengine/pkg/types"

	// Side-effect imports so the tool registry is populated for tests.
	_ "github.com/ClatTribe/tsengine/internal/tool/dalfox"
	_ "github.com/ClatTribe/tsengine/internal/tool/httpx"
	_ "github.com/ClatTribe/tsengine/internal/tool/nuclei"
	_ "github.com/ClatTribe/tsengine/internal/tool/sqlmap"
)

func TestHandler_TypeAndCatalog(t *testing.T) {
	h := NewHandler()
	if h.Type() != types.AssetWebApplication {
		t.Errorf("Type: got %q", h.Type())
	}
	names := names(h.Anchors())
	wantAnchors := []string{"nuclei", "dalfox", "httpx", "sqlmap"}
	if !equal(names, wantAnchors) {
		t.Errorf("Anchors: got %v, want %v", names, wantAnchors)
	}
}

func TestFilter_DropsStaticAssets(t *testing.T) {
	h := NewHandler()
	asset := types.Asset{Type: types.AssetWebApplication, Target: "https://example.com"}
	dispatches := []asset0Dispatch{
		{tool: "nuclei", target: "https://example.com/index.html"},
		{tool: "nuclei", target: "https://example.com/style.css"},
		{tool: "nuclei", target: "https://example.com/logo.png"},
		{tool: "nuclei", target: "https://example.com/app.bundle.js"},
	}
	in := materialize(dispatches)
	out := h.Filter(context.Background(), asset, in)
	if len(out) != 1 {
		t.Fatalf("Filter kept %d; want 1 (only index.html)", len(out))
	}
}

func TestFilter_ScopeKeepsSubdomain(t *testing.T) {
	h := NewHandler()
	a := types.Asset{Type: types.AssetWebApplication, Target: "https://example.com"}
	in := materialize([]asset0Dispatch{
		{tool: "nuclei", target: "https://example.com/api"},
		{tool: "nuclei", target: "https://api.example.com/v1"},
		{tool: "nuclei", target: "https://attacker.com/x"},
	})
	out := h.Filter(context.Background(), a, in)
	if len(out) != 2 {
		t.Fatalf("Filter kept %d; want 2 (off-host attacker.com dropped)", len(out))
	}
}

func TestFilter_ScopeWhitelist(t *testing.T) {
	h := NewHandler()
	a := types.Asset{
		Type:   types.AssetWebApplication,
		Target: "https://example.com",
		Scope:  types.Scope{ScopeHosts: []string{"cdn.partner.io"}},
	}
	in := materialize([]asset0Dispatch{
		{tool: "nuclei", target: "https://cdn.partner.io/asset"},
	})
	out := h.Filter(context.Background(), a, in)
	if len(out) != 1 {
		t.Errorf("scope_hosts whitelist not honored; out=%v", names(toolList(out)))
	}
}

func TestFilter_ScopeDeny(t *testing.T) {
	h := NewHandler()
	a := types.Asset{
		Type:   types.AssetWebApplication,
		Target: "https://example.com",
		Scope:  types.Scope{OutOfScope: []string{"api.example.com"}},
	}
	in := materialize([]asset0Dispatch{
		{tool: "nuclei", target: "https://api.example.com/x"},
		{tool: "nuclei", target: "https://example.com/x"},
	})
	out := h.Filter(context.Background(), a, in)
	if len(out) != 1 {
		t.Fatalf("OutOfScope not honored; kept %d", len(out))
	}
}

func TestFilter_LoginProtection(t *testing.T) {
	h := NewHandler()
	a := types.Asset{Type: types.AssetWebApplication, Target: "https://example.com"}

	// Build a mock destructive tool — sqlmap by name — so we can exercise
	// the destructiveTools routing rule without registering a real wrapper.
	in := []asset.Dispatch{
		{Tool: &mockTool{name: "sqlmap"}, Args: tool.Args{"target": "https://example.com/login"}},
		{Tool: &mockTool{name: "sqlmap"}, Args: tool.Args{"target": "https://example.com/items"}},
		{Tool: &mockTool{name: "nuclei"}, Args: tool.Args{"target": "https://example.com/login"}},
	}
	out := h.Filter(context.Background(), a, in)
	// sqlmap on /login dropped; sqlmap on /items kept; nuclei on /login kept.
	if len(out) != 2 {
		t.Fatalf("login protection: kept %d, want 2", len(out))
	}
	for _, d := range out {
		if d.Tool.Name() == "sqlmap" && d.Args["target"] == "https://example.com/login" {
			t.Errorf("sqlmap should have been dropped from /login")
		}
	}
}

func TestNormalize_AssignsIDsAndCarriesFields(t *testing.T) {
	results := []tool.Result{
		{
			Findings: []types.SandboxEmittedFinding{
				{RuleID: "nuclei::a", Tool: "nuclei", Severity: types.SeverityHigh, Title: "A"},
				{RuleID: "nuclei::b", Tool: "nuclei", Severity: types.SeverityLow, Title: "B"},
			},
		},
		{
			Findings: []types.SandboxEmittedFinding{
				{RuleID: "dalfox::xss", Tool: "dalfox", Severity: types.SeverityHigh, Title: "X"},
			},
		},
	}
	out := normalize(results)
	if len(out) != 3 {
		t.Fatalf("got %d findings; want 3", len(out))
	}
	wantIDs := []string{"f-0001", "f-0002", "f-0003"}
	for i, want := range wantIDs {
		if out[i].ID != want {
			t.Errorf("ID[%d]: got %q, want %q", i, out[i].ID, want)
		}
		if out[i].DiscoveredAt.IsZero() {
			t.Errorf("DiscoveredAt[%d] is zero", i)
		}
	}
	if out[2].Tool != "dalfox" {
		t.Errorf("tool attribution lost: %q", out[2].Tool)
	}
}

// --- test helpers ------------------------------------------------

type asset0Dispatch struct {
	tool   string
	target string
}

func materialize(in []asset0Dispatch) []asset.Dispatch {
	out := make([]asset.Dispatch, 0, len(in))
	for _, d := range in {
		t, _ := tool.Get(d.tool)
		if t == nil {
			t = &mockTool{name: d.tool}
		}
		out = append(out, asset.Dispatch{Tool: t, Args: tool.Args{"target": d.target}})
	}
	return out
}

type mockTool struct{ name string }

func (m *mockTool) Name() string                                      { return m.name }
func (*mockTool) SandboxExecution() bool                              { return true }
func (*mockTool) MITRETechniques() []string                           { return nil }
func (*mockTool) Run(context.Context, tool.Args) (tool.Result, error) { return tool.Result{}, nil }

func names(in []tool.Tool) []string {
	out := make([]string, 0, len(in))
	for _, t := range in {
		out = append(out, t.Name())
	}
	return out
}

func toolList(in []asset.Dispatch) []tool.Tool {
	out := make([]tool.Tool, 0, len(in))
	for _, d := range in {
		out = append(out, d.Tool)
	}
	return out
}

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
