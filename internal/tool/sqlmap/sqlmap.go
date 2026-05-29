// Package sqlmap wraps the sqlmap SQL-injection scanner as a tsengine
// Tool. It's the web_application asset's SQLi specialist — the tool that
// fills WAVSEP's sqli category (where nuclei templates alone under-score).
// Registers via init().
//
// sqlmap is destructive-ish (it issues many injection payloads), so the
// web filter's login-protection routing skips it on auth endpoints and
// the W3 wave classifier orders it after any auth capture.
package sqlmap

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"

	"github.com/ClatTribe/tsengine/internal/tool"
)

// Sqlmap is the tool.Tool implementation.
type Sqlmap struct{}

// New constructs a Sqlmap wrapper.
func New() *Sqlmap { return &Sqlmap{} }

func (*Sqlmap) Name() string              { return "sqlmap" }
func (*Sqlmap) SandboxExecution() bool    { return true }
func (*Sqlmap) MITRETechniques() []string { return []string{"T1190"} }

// defaultTechnique is the fast anchor technique set: (B)oolean-blind,
// (E)rror-based, (U)nion. It deliberately OMITS (T)ime-based blind and
// (S)tacked queries — time-based *sleeps* per payload, so on a case sqlmap
// can't quickly confirm (the WAVSEP false-positive/blind cases, and any
// multi-param form) the full BEUSTQ matrix runs for minutes and blows the
// per-tool timeout, killing the dispatch with ZERO findings. Measured on
// WAVSEP: a 2-param login case takes 2m11s with all techniques vs 1.3s with
// BEU — a ~100× speedup that still flags the injection. Per-URL anchor speed
// is what lets the whole fan-out finish; the slower techniques are available
// on demand via the `technique` arg (escalation / tool-replay "dig deeper").
const defaultTechnique = "BEU"

// Run probes a single URL for SQL injection.
//
// Recognized args:
//
//	"target"    string — required, the URL (with the param to test).
//	"data"      string — optional POST body (switches sqlmap to POST).
//	"method"    string — optional HTTP method.
//	"cookie"    string — optional session cookie (authed scans).
//	"technique" string — optional sqlmap technique letters (default "BEU");
//	                     pass "BEUST"/"BEUSTQ" via escalation/replay for depth.
//	"level"     string — optional sqlmap --level (1–5).
//	"risk"      string — optional sqlmap --risk (1–3).
//
// sqlmap has no clean machine output, so we run it batch/non-interactive
// and parse its stdout injection-point report. Output: confirmed
// injections become CWE-89 findings; raw stdout is preserved.
func (*Sqlmap) Run(ctx context.Context, args tool.Args) (tool.Result, error) {
	target, _ := args["target"].(string)
	if strings.TrimSpace(target) == "" {
		return tool.Result{}, errors.New("sqlmap: missing required arg 'target'")
	}
	technique := defaultTechnique
	if t, ok := args["technique"].(string); ok && strings.TrimSpace(t) != "" {
		technique = strings.TrimSpace(t)
	}
	cli := []string{
		"-u", target,
		"--batch",                // non-interactive (answer prompts with defaults)
		"--disable-coloring",     // clean stdout for parsing
		"--flush-session",        // reproducible — don't reuse cached results
		"--technique", technique, // fast BEU by default (see defaultTechnique)
		"--smart",        // heuristic-gate params — skip the non-injectable fast
		"--timeout", "8", // HTTP connect/read cap so a slow response can't stall
		"--retries", "1", // one retry, then move on
		"-v", "1",
	}
	if lv, ok := args["level"].(string); ok && lv != "" {
		cli = append(cli, "--level", lv)
	}
	if rk, ok := args["risk"].(string); ok && rk != "" {
		cli = append(cli, "--risk", rk)
	}
	if d, ok := args["data"].(string); ok && d != "" {
		cli = append(cli, "--data", d)
	}
	if m, ok := args["method"].(string); ok && m != "" {
		cli = append(cli, "--method", m)
	}
	if c, ok := args["cookie"].(string); ok && c != "" {
		cli = append(cli, "--cookie", c)
	}

	cmd := exec.CommandContext(ctx, "sqlmap", cli...)
	stdout, err := cmd.Output()
	if err != nil {
		var ee *exec.ExitError
		if !errors.As(err, &ee) {
			return tool.Result{}, fmt.Errorf("sqlmap: exec: %w", err)
		}
		// sqlmap exits non-zero in some no-vuln paths; parse stdout anyway.
	}
	return tool.Result{Output: string(stdout), Findings: parse(stdout, target)}, nil
}

// KnownArgs declares the recognized arg keys (tool.ArgSpec).
func (*Sqlmap) KnownArgs() []string {
	return []string{"target", "data", "method", "cookie", "technique", "level", "risk"}
}

func init() { tool.Register(New()) }
