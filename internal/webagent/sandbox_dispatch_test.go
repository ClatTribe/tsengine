package webagent

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/internal/tool"
)

// fakeExecutor stands in for *sandbox.Client — records the call, returns a canned Result/err.
type fakeExecutor struct {
	gotTool string
	gotArgs tool.Args
	res     tool.Result
	err     error
}

func (f *fakeExecutor) Execute(_ context.Context, name string, args tool.Args) (tool.Result, error) {
	f.gotTool, f.gotArgs = name, args
	return f.res, f.err
}

// TestSandboxDispatcher_PassesThroughAndRenders: the adapter forwards tool+args to the Executor and
// renders a string Output verbatim.
func TestSandboxDispatcher_PassesThroughAndRenders(t *testing.T) {
	fx := &fakeExecutor{res: tool.Result{Output: "Database: app\nTable: users\nflag: FLAG{sqlmap}"}}
	d := SandboxDispatcher(fx)
	if d == nil {
		t.Fatal("non-nil executor should yield a dispatcher")
	}
	out, err := d.RunTool(context.Background(), "sqlmap", map[string]any{"url": "http://t/x?id=1", "technique": "B"})
	if err != nil {
		t.Fatalf("RunTool: %v", err)
	}
	if fx.gotTool != "sqlmap" || fx.gotArgs["technique"] != "B" {
		t.Errorf("tool/args not passed through: %s %+v", fx.gotTool, fx.gotArgs)
	}
	if !strings.Contains(out, "FLAG{sqlmap}") {
		t.Errorf("string output not rendered: %s", out)
	}
}

// TestSandboxDispatcher_RendersStructuredOutput: a structured (non-string) Output is JSON-encoded so
// the agent sees the whole shape, not a lossy %v.
func TestSandboxDispatcher_RendersStructuredOutput(t *testing.T) {
	fx := &fakeExecutor{res: tool.Result{Output: map[string]any{"dbs": []string{"information_schema", "app"}}}}
	out, err := SandboxDispatcher(fx).RunTool(context.Background(), "sqlmap", nil)
	if err != nil {
		t.Fatalf("RunTool: %v", err)
	}
	if !strings.Contains(out, "information_schema") || !strings.Contains(out, `"dbs"`) {
		t.Errorf("structured output not JSON-rendered: %s", out)
	}
}

// TestSandboxDispatcher_Error: an Executor error surfaces as an error (never a fake success).
func TestSandboxDispatcher_Error(t *testing.T) {
	fx := &fakeExecutor{err: errors.New("tool-server 500")}
	if _, err := SandboxDispatcher(fx).RunTool(context.Background(), "nuclei", nil); err == nil {
		t.Error("executor error should surface, not be swallowed")
	}
}

// TestSandboxDispatcher_NilExecutor: a nil Executor yields a nil Dispatcher — the caller can wire it
// unconditionally and dispatch_oss then reports the tool unavailable (never pretends).
func TestSandboxDispatcher_NilExecutor(t *testing.T) {
	if d := SandboxDispatcher(nil); d != nil {
		t.Errorf("nil executor must yield nil dispatcher, got %T", d)
	}
	// End-to-end nil-safety: a nil dispatcher flows into the tool and degrades gracefully.
	cc := &Context{ctx: context.Background(), dispatcher: SandboxDispatcher(nil)}
	if out := tDispatchOSS(cc, map[string]any{"tool": "sqlmap"}); !strings.Contains(out, "unavailable") {
		t.Errorf("nil sandbox dispatcher should degrade gracefully in the tool: %s", out)
	}
}
