package webagent

import (
	"context"
	"fmt"
	"strings"
	"testing"
)

// fakeDispatcher records the tool+args and returns a canned result (stands in for the sandbox tool-server).
type fakeDispatcher struct {
	gotTool string
	gotArgs map[string]any
	out     string
	err     error
}

func (f *fakeDispatcher) RunTool(_ context.Context, tool string, args map[string]any) (string, error) {
	f.gotTool, f.gotArgs = tool, args
	return f.out, f.err
}

// TestDispatchOSS_RoutesToDispatcher: dispatch_oss hands a known tool + its args to the Dispatcher and
// surfaces the result, recording an evidence Turn.
func TestDispatchOSS_RoutesToDispatcher(t *testing.T) {
	fd := &fakeDispatcher{out: "available databases [2]:\n[*] information_schema\n[*] app\nflag: FLAG{extracted}"}
	cc := &Context{ctx: context.Background(), dispatcher: fd}
	out := tDispatchOSS(cc, map[string]any{
		"tool": "sqlmap",
		"args": map[string]any{"url": "http://t/x?id=1", "technique": "B"},
	})
	if fd.gotTool != "sqlmap" {
		t.Errorf("dispatcher got tool %q, want sqlmap", fd.gotTool)
	}
	if fmt.Sprint(fd.gotArgs["url"]) != "http://t/x?id=1" {
		t.Errorf("tool args not passed through: %+v", fd.gotArgs)
	}
	if !strings.Contains(out, "FLAG{extracted}") {
		t.Errorf("dispatcher result not surfaced: %s", out)
	}
	if len(cc.History) != 1 || !strings.HasPrefix(cc.History[0].Method, "dispatch:") {
		t.Errorf("no evidence Turn recorded for the dispatch: %+v", cc.History)
	}
}

// TestDispatchOSS_NilDispatcher: without a wired Dispatcher (standalone host-side run) it degrades
// gracefully and says so — never pretends the tool ran.
func TestDispatchOSS_NilDispatcher(t *testing.T) {
	cc := &Context{ctx: context.Background()} // dispatcher nil
	out := tDispatchOSS(cc, map[string]any{"tool": "sqlmap"})
	if !strings.Contains(out, "unavailable") {
		t.Errorf("nil dispatcher should degrade gracefully: %s", out)
	}
	if len(cc.History) != 0 {
		t.Errorf("nil dispatch must not record a Turn (nothing ran): %+v", cc.History)
	}
}

// TestDispatchOSS_UnknownTool: an unknown tool is rejected with the available list (no dispatch).
func TestDispatchOSS_UnknownTool(t *testing.T) {
	cc := &Context{ctx: context.Background(), dispatcher: &fakeDispatcher{}}
	if out := tDispatchOSS(cc, map[string]any{"tool": "metasploit"}); !strings.Contains(out, "unknown OSS tool") {
		t.Errorf("unknown tool not rejected: %s", out)
	}
	if out := tDispatchOSS(cc, map[string]any{}); !strings.Contains(out, "tool is required") {
		t.Errorf("missing tool not handled: %s", out)
	}
}
