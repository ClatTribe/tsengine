// Package katana wraps the projectdiscovery/katana web crawler as a
// tsengine recon Tool. Unlike detection tools, katana produces the scan
// SURFACE — the URLs the web Handler fans detection tools across — not
// findings. Those URLs ride back in Result.DiscoveredURLs.
//
// katana is sandbox-routed from line 1 (the Tool interface enforces it).
// strix originally shipped crawl as a host-side helper (_katana_crawl)
// that bypassed the sandbox dispatch and broke L1.5 hooks + telemetry;
// it had to migrate to a registered sandbox tool in iter-35.1
// (CLAUDE.md §10). tsengine skips that mistake by construction.
package katana

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strconv"
	"strings"

	"github.com/ClatTribe/tsengine/internal/tool"
)

// Katana is the tool.Tool implementation.
type Katana struct{}

// New constructs a Katana wrapper.
func New() *Katana { return &Katana{} }

func (*Katana) Name() string              { return "katana" }
func (*Katana) SandboxExecution() bool    { return true }
func (*Katana) MITRETechniques() []string { return []string{"T1595.002"} }

// Run crawls the target and returns discovered URLs in
// Result.DiscoveredURLs.
//
// Recognized args:
//
//	"target" string — required, the URL to crawl from.
//	"depth"  int    — optional crawl depth (default 2).
func (*Katana) Run(ctx context.Context, args tool.Args) (tool.Result, error) {
	target, _ := args["target"].(string)
	if strings.TrimSpace(target) == "" {
		return tool.Result{}, errors.New("katana: missing required arg 'target'")
	}
	depth := "2"
	if d, ok := tool.ArgInt(args, "depth"); ok && d > 0 {
		depth = strconv.Itoa(d)
	}
	cmd := exec.CommandContext(ctx, "katana",
		"-u", target, "-jsonl", "-silent", "-nc",
		"-d", depth,
		"-c", "5", // crawl concurrency inside katana (lowered from 10 to cap peak memory)
		// MEMORY BOUNDS. A heavy SPA (large JS bundles + many dynamic routes) made katana's -jc/-jsl JS
		// analysis accumulate UNBOUNDED memory, and the sandbox cgroup OOM-killer SIGKILLed it: measured on
		// a real Next.js site it filled whatever limit it was given — ~4GB at a 4g cap, ~6GB at a 6g cap —
		// so raising the limit never helps, it just raises the ceiling it fills. The result was a DEGRADED
		// pass (katana "failed", its surface lost). These two caps keep the crawl bounded and make katana
		// EXIT NORMALLY with a partial surface instead of being killed, so the pass is complete, not degraded:
		"-mrs", "1048576", // max response size 1MB — don't read a huge JS bundle whole (a direct OOM cause)
		"-ct", "3m", // crawl-duration cap — after 3m katana stops gracefully and returns what it found so far
		"-fx", // form extraction: emit each page's forms (method/action/params)
		"-jc", // JS crawl: parse endpoints out of linked JavaScript. Modern apps are SPAs (Angular/React)
		//       whose routes + REST/API endpoints live ONLY in the JS bundle — a plain HTML crawl sees
		//       one URL (the empty shell). -jc recovers the real surface WITHOUT a headless browser
		//       (no Chromium needed): measured 1 → 1817 URLs on OWASP Juice Shop. The fan-out cap
		//       (TSENGINE_FANOUT_MAX_URLS) + surface filtration keep the larger surface bounded.
		// -jsl (jsluice deep JS extraction) was REMOVED: it was the primary memory hog — on a large Next.js
		// SPA its regex analysis of big JS bundles grew UNBOUNDED and OOM-killed the sandbox even at 6GB,
		// marking the whole web scan DEGRADED. -jc alone reaches the JS-defined surface (measured 29k URLs
		// in ~84s on a real app) and completes cleanly, so the pass is complete instead of degraded.
	)
	stdout, err := cmd.Output()
	if err != nil {
		if tool.DidNotRun(err) {
			return tool.Result{}, fmt.Errorf("katana: exec: %w", err)
		}
	}
	urls := parse(stdout)
	return tool.Result{Output: string(stdout), DiscoveredURLs: urls}, nil
}

// KnownArgs declares the recognized arg keys (tool.ArgSpec).
func (*Katana) KnownArgs() []string { return []string{"target", "depth"} }

func init() { tool.Register(New()) }
