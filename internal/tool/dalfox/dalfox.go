// Package dalfox wraps the hahwul/dalfox XSS scanner as a tsengine Tool.
//
// Imports this package register the wrapper in the global tool.Registry
// via init().
package dalfox

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"

	"github.com/ClatTribe/tsengine/internal/tool"
)

// Dalfox is the tool.Tool implementation.
type Dalfox struct{}

// New constructs a Dalfox wrapper.
func New() *Dalfox { return &Dalfox{} }

func (*Dalfox) Name() string             { return "dalfox" }
func (*Dalfox) SandboxExecution() bool   { return true }
func (*Dalfox) MITRETechniques() []string { return []string{"T1059.007"} }

// Run invokes the dalfox CLI in URL mode.
//
// Recognized args:
//
//	"target" string — required, the URL or endpoint to test
//	"method" string — optional GET/POST (default GET)
//	"data"   string — optional POST body for method=POST
//	"params" string — optional comma-separated parameters to focus
//	"timeout" int   — optional per-request timeout seconds
//
// Output ends up in Result.Findings; Result.Output carries the raw
// JSON / JSONL blob for the security engineer view.
func (*Dalfox) Run(ctx context.Context, args tool.Args) (tool.Result, error) {
	target, _ := args["target"].(string)
	if strings.TrimSpace(target) == "" {
		return tool.Result{}, errors.New("dalfox: missing required arg 'target'")
	}

	cliArgs := []string{"url", target, "--format", "json", "--no-color", "--silence"}
	if m, ok := args["method"].(string); ok && m != "" {
		cliArgs = append(cliArgs, "--method", m)
	}
	if d, ok := args["data"].(string); ok && d != "" {
		cliArgs = append(cliArgs, "--data", d)
	}
	if p, ok := args["params"].(string); ok && p != "" {
		cliArgs = append(cliArgs, "--param", p)
	}
	if c, ok := args["cookie"].(string); ok && c != "" {
		cliArgs = append(cliArgs, "--cookie", c)
	}
	if to, ok := args["timeout"].(int); ok && to > 0 {
		cliArgs = append(cliArgs, "--timeout", fmt.Sprintf("%d", to))
	}

	cmd := exec.CommandContext(ctx, "dalfox", cliArgs...)
	stdout, err := cmd.Output()
	if err != nil {
		var ee *exec.ExitError
		if !errors.As(err, &ee) {
			return tool.Result{}, fmt.Errorf("dalfox: exec: %w", err)
		}
		// dalfox can exit non-zero on findings/parse issues; still try
		// to parse stdout.
	}

	findings := parseAny(stdout)
	return tool.Result{
		Output:   string(stdout),
		Findings: findings,
	}, nil
}

func init() {
	tool.Register(New())
}
