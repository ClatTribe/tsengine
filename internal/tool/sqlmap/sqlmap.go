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

// Run probes a single URL for SQL injection.
//
// Recognized args:
//
//	"target" string — required, the URL (with the param to test).
//	"data"   string — optional POST body (switches sqlmap to POST).
//	"method" string — optional HTTP method.
//
// sqlmap has no clean machine output, so we run it batch/non-interactive
// and parse its stdout injection-point report. Output: confirmed
// injections become CWE-89 findings; raw stdout is preserved.
func (*Sqlmap) Run(ctx context.Context, args tool.Args) (tool.Result, error) {
	target, _ := args["target"].(string)
	if strings.TrimSpace(target) == "" {
		return tool.Result{}, errors.New("sqlmap: missing required arg 'target'")
	}
	cli := []string{
		"-u", target,
		"--batch",            // non-interactive (answer prompts with defaults)
		"--disable-coloring", // clean stdout for parsing
		"--flush-session",    // reproducible — don't reuse cached results
		"-v", "1",
	}
	if d, ok := args["data"].(string); ok && d != "" {
		cli = append(cli, "--data", d)
	}
	if m, ok := args["method"].(string); ok && m != "" {
		cli = append(cli, "--method", m)
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

func init() { tool.Register(New()) }
