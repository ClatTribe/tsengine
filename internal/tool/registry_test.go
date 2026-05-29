package tool

import (
	"context"
	"strings"
	"testing"
)

type fakeTool struct {
	name        string
	sandbox     bool
	mitre       []string
	runResponse Result
}

func (f *fakeTool) Name() string                              { return f.name }
func (f *fakeTool) SandboxExecution() bool                    { return f.sandbox }
func (f *fakeTool) MITRETechniques() []string                 { return f.mitre }
func (f *fakeTool) Run(context.Context, Args) (Result, error) { return f.runResponse, nil }

func TestRegister_RoundTrip(t *testing.T) {
	defer reset()
	reset()

	tool := &fakeTool{name: "nuclei", sandbox: true, mitre: []string{"T1190"}}
	Register(tool)

	got, ok := Get("nuclei")
	if !ok {
		t.Fatal("Get(nuclei) returned !ok")
	}
	if got.Name() != "nuclei" {
		t.Errorf("Get returned wrong tool: %q", got.Name())
	}
	if !got.SandboxExecution() {
		t.Error("SandboxExecution lost in registry")
	}
}

func TestRegister_DuplicatePanics(t *testing.T) {
	defer reset()
	reset()
	Register(&fakeTool{name: "nuclei", sandbox: true})

	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("expected panic on duplicate register; got none")
		}
		if !strings.Contains(r.(string), "duplicate tool name") {
			t.Errorf("unexpected panic message: %v", r)
		}
	}()
	Register(&fakeTool{name: "nuclei", sandbox: true})
}

func TestRegister_EmptyNamePanics(t *testing.T) {
	defer reset()
	reset()
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic on empty name; got none")
		}
	}()
	Register(&fakeTool{name: ""})
}

func TestAll_DeterministicOrder(t *testing.T) {
	defer reset()
	reset()
	Register(&fakeTool{name: "trivy"})
	Register(&fakeTool{name: "nuclei"})
	Register(&fakeTool{name: "sqlmap"})

	all := All()
	if len(all) != 3 {
		t.Fatalf("All(): got %d, want 3", len(all))
	}
	wantOrder := []string{"nuclei", "sqlmap", "trivy"}
	for i, want := range wantOrder {
		if all[i].Name() != want {
			t.Errorf("All()[%d]: got %q, want %q", i, all[i].Name(), want)
		}
	}
}

func TestGet_MissingReturnsFalse(t *testing.T) {
	defer reset()
	reset()
	if _, ok := Get("nonexistent"); ok {
		t.Error("Get(nonexistent) returned ok=true")
	}
}
