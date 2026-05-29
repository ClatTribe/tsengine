package adapters

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/internal/replay"
	"github.com/ClatTribe/tsengine/internal/tool"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// --- replay test doubles --------------------------------------------------

type mockDispatcher struct {
	result  tool.Result
	err     error
	gotTool string
	gotArgs tool.Args
}

func (m *mockDispatcher) Execute(_ context.Context, name string, args tool.Args) (tool.Result, error) {
	m.gotTool, m.gotArgs = name, args
	return m.result, m.err
}

type mockSpawner struct{ disp replay.Dispatcher }

func (m *mockSpawner) Spawn(_ context.Context, _ string) (replay.Dispatcher, func(context.Context) error, error) {
	return m.disp, func(context.Context) error { return nil }, nil
}

// writeScan persists a minimal scan with a pinned image digest (Replay
// requires one) so loadScan succeeds.
func writeScan(t *testing.T, runsDir, scanID string) {
	t.Helper()
	dir := filepath.Join(runsDir, scanID)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	scan := types.Scan{
		ScanID: scanID,
		Asset:  types.Asset{Type: types.AssetWebApplication, Target: "https://example.com"},
		Engine: types.Engine{SandboxImageDigest: "sha256:deadbeef"},
	}
	b, _ := json.Marshal(scan)
	if err := os.WriteFile(filepath.Join(dir, "vulnerabilities.json"), b, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestProber_RendersFindingsAndRoutesTarget(t *testing.T) {
	runs := t.TempDir()
	writeScan(t, runs, "scan-abc")
	disp := &mockDispatcher{result: tool.Result{Findings: []types.SandboxEmittedFinding{
		{RuleID: "sqlmap::sqli", Tool: "sqlmap", Severity: types.SeverityCritical,
			Title: "SQL injection confirmed", Endpoint: "https://x/p?id=1"},
	}}}
	p := NewProber("scan-abc", runs, &mockSpawner{disp: disp})

	out, err := p.Probe(context.Background(), "sqlmap", map[string]any{
		"target": "https://x/p?id=1", "level": "3",
	})
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	// target is pulled out as the replay override (not left in args), level
	// rides through as a tool arg.
	if disp.gotArgs["target"] != "https://x/p?id=1" {
		t.Errorf("target not routed: %v", disp.gotArgs)
	}
	if disp.gotArgs["level"] != "3" {
		t.Errorf("extra arg not forwarded: %v", disp.gotArgs)
	}
	for _, want := range []string{"sqlmap", "SQL injection confirmed", "critical"} {
		if !strings.Contains(out, want) {
			t.Errorf("probe summary missing %q in:\n%s", want, out)
		}
	}
}

func TestProber_NoFindings(t *testing.T) {
	runs := t.TempDir()
	writeScan(t, runs, "scan-abc")
	p := NewProber("scan-abc", runs, &mockSpawner{disp: &mockDispatcher{}})
	out, err := p.Probe(context.Background(), "nuclei", map[string]any{"target": "https://x"})
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	if !strings.Contains(out, "no findings") {
		t.Errorf("expected a no-findings summary, got %q", out)
	}
}

func TestProber_ReplayError(t *testing.T) {
	runs := t.TempDir()
	writeScan(t, runs, "scan-abc")
	p := NewProber("scan-abc", runs, &mockSpawner{disp: &mockDispatcher{err: errors.New("sandbox boom")}})
	if _, err := p.Probe(context.Background(), "sqlmap", map[string]any{"target": "https://x"}); err == nil {
		t.Error("a replay error should propagate")
	}
}
