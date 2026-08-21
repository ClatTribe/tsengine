// Package tool defines the Tool interface every OSS wrapper implements,
// and the global registry the orchestrator + sandbox tool-server both
// look up by name. See CLAUDE.md §12.3.
package tool

import (
	"context"
	"encoding/json"
	"math"

	"github.com/ClatTribe/tsengine/pkg/types"
)

// Tool wraps a single OSS scanner or framework primitive. One Tool impl
// per OSS tool. Implementations register themselves via Register() from
// their package init() so cmd/tsengine and cmd/tool-server share a
// single source of truth at startup.
type Tool interface {
	// Name is the stable identifier for this tool. Used for dispatch,
	// catalog membership, and finding attribution (Finding.Tool). Must
	// be unique across all registered tools.
	Name() string

	// SandboxExecution reports whether this tool must dispatch into the
	// sandbox container. Default for any new wrapper is true; opt out
	// only for host-only framework state-management tools (workflow,
	// tracer, finish_scan).
	SandboxExecution() bool

	// MITRETechniques returns the MITRE ATT&CK technique IDs this tool's
	// findings are attributed to. Surfaced in the L1 dashboard.
	MITRETechniques() []string

	// Run executes the tool. On the host this is invoked via the
	// sandbox HTTP client; on the sandbox side it's invoked by the
	// tool-server directly. Implementations MUST honor ctx.Done().
	Run(ctx context.Context, args Args) (Result, error)
}

// Args is the per-call argument bag. Wrapped tools project these into
// CLI flags / library options.
type Args map[string]any

// ArgSpec is an OPTIONAL interface a Tool may implement to declare the arg
// keys it recognizes. It exists to kill a whole class of silent-recall
// bug: strix passed args by string key with no contract, so a Handler that
// dispatched a tool with the wrong key ("url" vs "target") had its args
// silently ignored — dropping 5+ anchor signals per target with no error.
// A CI test (internal/asset arg-contract test) asserts every key a Handler
// dispatches is in the tool's KnownArgs, turning a mis-wire into a loud
// build failure instead of zero recall. Tools that don't implement it are
// skipped by the check (back-compat).
type ArgSpec interface {
	// KnownArgs returns the arg keys this tool reads in Run. Keys a
	// Handler passes that aren't listed are a contract violation.
	KnownArgs() []string
}

// ArgIsKnown reports whether key is recognized by t. Tools that don't
// implement ArgSpec are treated as accepting any key (returns true).
func ArgIsKnown(t Tool, key string) bool {
	spec, ok := t.(ArgSpec)
	if !ok {
		return true
	}
	for _, k := range spec.KnownArgs() {
		if k == key {
			return true
		}
	}
	return false
}

// Result is the wire format every tool returns. Findings are the
// host-shape findings the tool emits explicitly; SandboxEmittedFindings
// is the sidecar channel populated by the tool-server when the tool
// internally called the sandbox-side tracer (CLAUDE.md §12.4).
//
// Output is opaque tool-specific payload preserved for the security
// engineer audience — written into Finding.RawOutput by the host
// normalization step.
type Result struct {
	Output                 any                           `json:"output,omitempty"`
	Findings               []types.SandboxEmittedFinding `json:"findings,omitempty"`
	SandboxEmittedFindings []types.SandboxEmittedFinding `json:"_sandbox_emitted_findings,omitempty"`

	// DiscoveredURLs is the recon channel: surface-discovery tools
	// (katana, openapi_ingest) return the URLs/endpoints they found
	// here, NOT as findings. The orchestrator's recon stage collects
	// these into the scan surface that detection tools fan out across.
	DiscoveredURLs []string `json:"discovered_urls,omitempty"`

	// CapturedSession is the auth channel: seed_auth returns a captured
	// session cookie here. It rides the sandbox→host transport (this
	// Result) but is NEVER part of the dashboard (vulnerabilities.json is
	// types.Scan, which doesn't embed Result) — so the live credential
	// never lands on disk. The orchestrator threads it into later-wave
	// (authed) dispatches' args["cookie"] (CLAUDE.md §11 wave ordering).
	CapturedSession string `json:"captured_session,omitempty"`
}

// ArgInt reads an integer argument, tolerating every shape it can arrive in.
//
// THIS EXISTS BECAUSE `args["depth"].(int)` IS WRONG EVERYWHERE THAT MATTERS.
// Args is map[string]any, and a dispatch crosses the host→sandbox boundary as JSON
// (§12.3). encoding/json decodes every number into float64, so an int written by a
// handler comes back as float64 and a direct .(int) assertion FAILS — in the sandbox,
// which is to say in production. It succeeds in unit tests, which never serialize.
//
// The failure is silent and expensive. katana's crawl depth is the worst case measured:
// the web handler sets depth 3 precisely because "depth 2 is too shallow to discover a
// real app's surface", the assertion failed in the sandbox, katana fell back to 2, and a
// live WAVSEP crawl returned 68 URLs where depth 3 returns 1,604. A 96% surface loss on
// every sandboxed web scan, reported as a successful scan.
//
// Accepts int, int64, float64 and json.Number. A float with a fractional part is REFUSED
// rather than truncated: 2.7 is not something a caller meant as a count, and silently
// making it 2 would repeat this bug's defining feature — a value quietly becoming
// something other than what was written.
func ArgInt(args Args, key string) (int, bool) {
	switch v := args[key].(type) {
	case int:
		return v, true
	case int64:
		return int(v), true
	case float64:
		if v != math.Trunc(v) {
			return 0, false
		}
		return int(v), true
	case json.Number:
		n, err := v.Int64()
		if err != nil {
			return 0, false
		}
		return int(n), true
	}
	return 0, false
}

// ArgBool reads a boolean argument. JSON round-trips bool faithfully, so this is a
// convenience rather than a fix — but it keeps every wrapper reading args the same way,
// which is what stops the next one reaching for a bare type assertion.
func ArgBool(args Args, key string) bool {
	b, _ := args[key].(bool)
	return b
}
