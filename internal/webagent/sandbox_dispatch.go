package webagent

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/ClatTribe/tsengine/internal/tool"
)

// sandbox_dispatch.go is the LIVE half of the §13 OSS-dispatch seam (the other half is the
// Dispatcher interface + dispatch_oss tool in dispatch.go). It adapts the SAME sandbox executor
// the L1 orchestrator uses — anything exposing Execute(ctx, tool, tool.Args) (tool.Result, error),
// satisfied by *sandbox.Client and orchestrator.Dispatcher — to the webagent's string-based
// Dispatcher. So when a run has a spawned sandbox, dispatch_oss hands sqlmap/wpscan/nuclei/… to the
// real sandbox tool-server; when it doesn't, the caller passes nil and the agent degrades gracefully.
//
// This keeps ONE dispatch path (§9: dispatch_l2_probe is a thin wrapper over the same /replay
// handler) — the offensive agent doesn't get a second, divergent way to run OSS tools.

// Executor is the minimal sandbox seam the live Dispatcher needs. *sandbox.Client and
// orchestrator.Dispatcher both satisfy it, so the caller injects whichever it already owns without
// a new dependency wiring.
type Executor interface {
	Execute(ctx context.Context, toolName string, args tool.Args) (tool.Result, error)
}

// SandboxDispatcher adapts a sandbox Executor to the webagent Dispatcher. A nil Executor returns a
// nil Dispatcher (dispatch_oss then reports the tool unavailable rather than pretending) — so a
// caller can wire it unconditionally: SandboxDispatcher(maybeNilClient).
func SandboxDispatcher(ex Executor) Dispatcher {
	if ex == nil {
		return nil
	}
	return &sandboxDispatcher{ex: ex}
}

type sandboxDispatcher struct{ ex Executor }

// RunTool runs one OSS specialist in the sandbox and renders its output as text for the agent. The
// args map passes straight through (tool.Args IS map[string]any) — the arg-contract CI test (§5.2 C4)
// still guards key names at the tool boundary.
func (d *sandboxDispatcher) RunTool(ctx context.Context, name string, args map[string]any) (string, error) {
	res, err := d.ex.Execute(ctx, name, tool.Args(args))
	if err != nil {
		return "", err
	}
	return renderToolOutput(res.Output), nil
}

// renderToolOutput turns a tool.Result.Output (string, or structured JSON) into the text the agent
// reads. A structured result is JSON-encoded so the model sees the whole shape (sqlmap's dumped
// tables, nuclei's matched templates) rather than a lossy %v.
func renderToolOutput(out any) string {
	switch v := out.(type) {
	case nil:
		return "(tool returned no output)"
	case string:
		return v
	default:
		if b, err := json.Marshal(v); err == nil {
			return string(b)
		}
		return fmt.Sprintf("%v", v)
	}
}
