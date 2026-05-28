// Package nuclei wraps the projectdiscovery/nuclei CLI as a tsengine
// Tool. The wrapper runs `nuclei -u <target> -jsonl` inside the sandbox
// container, parses the JSONL output, and returns canonical findings.
//
// Importing this package (even via blank import) registers the wrapper
// in the global tool registry — that's how cmd/tool-server and
// cmd/tsengine both pick it up.
package nuclei

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"

	"github.com/ClatTribe/tsengine/internal/tool"
)

// Nuclei is the tool.Tool implementation. Stateless; reuse one instance.
type Nuclei struct{}

// New constructs a Nuclei wrapper.
func New() *Nuclei { return &Nuclei{} }

// Name is the stable identifier — used in finding attribution and the
// tool catalog.
func (*Nuclei) Name() string { return "nuclei" }

// SandboxExecution: nuclei always runs in the sandbox (it needs the
// network namespace + binaries + templates installed there).
func (*Nuclei) SandboxExecution() bool { return true }

// MITRETechniques returns the broad ATT&CK technique bucket nuclei
// findings fall under. Per-template mapping is L1.5's job, not the
// tool's.
func (*Nuclei) MITRETechniques() []string {
	return []string{"T1595", "T1595.002"}
}

// Run invokes the nuclei CLI with the target from args. Recognized args:
//
//	"target"     string  — required
//	"templates"  string  — optional -t value (e.g. "cves/", "default-logins/")
//	"tags"       string  — optional -tags filter (comma-separated)
//	"rate_limit" int     — optional -rl value
//
// Output: the parsed findings end up in Result.Findings. Result.Output
// carries the raw JSONL blob for the security-engineer audience.
func (*Nuclei) Run(ctx context.Context, args tool.Args) (tool.Result, error) {
	target, _ := args["target"].(string)
	if strings.TrimSpace(target) == "" {
		return tool.Result{}, errors.New("nuclei: missing required arg 'target'")
	}

	cliArgs := []string{"-u", target, "-jsonl", "-silent", "-disable-update-check"}
	if t, ok := args["templates"].(string); ok && t != "" {
		cliArgs = append(cliArgs, "-t", t)
	}
	if tags, ok := args["tags"].(string); ok && tags != "" {
		cliArgs = append(cliArgs, "-tags", tags)
	}
	if rl, ok := args["rate_limit"].(int); ok && rl > 0 {
		cliArgs = append(cliArgs, "-rl", fmt.Sprintf("%d", rl))
	}

	cmd := exec.CommandContext(ctx, "nuclei", cliArgs...)
	stdout, err := cmd.Output()
	if err != nil {
		// nuclei exits non-zero when it finds nothing in some configs.
		// Treat exit-with-stdout as success; only true exec errors are
		// failures.
		var ee *exec.ExitError
		if !errors.As(err, &ee) {
			return tool.Result{}, fmt.Errorf("nuclei: exec: %w", err)
		}
		// Still try to parse stdout — partial output is valid.
	}

	findings := parseJSONL(stdout)
	return tool.Result{
		Output:   string(stdout),
		Findings: findings,
	}, nil
}

func init() {
	tool.Register(New())
}
