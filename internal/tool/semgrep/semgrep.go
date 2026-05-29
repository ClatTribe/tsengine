// Package semgrep wraps the semgrep SAST engine as a tsengine Tool.
// Used by the repository asset; it's the tool that puts tsengine on the
// OWASP Benchmark SAST leaderboard (CLAUDE.md §6.1). Registers via init().
package semgrep

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"

	"github.com/ClatTribe/tsengine/internal/tool"
)

// Semgrep is the tool.Tool implementation.
type Semgrep struct{}

// New constructs a Semgrep wrapper.
func New() *Semgrep { return &Semgrep{} }

func (*Semgrep) Name() string              { return "semgrep" }
func (*Semgrep) SandboxExecution() bool    { return true }
func (*Semgrep) MITRETechniques() []string { return []string{"T1059"} }

// Run scans a source tree with semgrep's curated security rulesets.
//
// Recognized args:
//
//	"target" string — required, path to the source tree (in-sandbox)
//	"config" string — optional override of the default ruleset config
//
// Default config is a security-focused bundle. The rulesets are
// pre-fetched into the sandbox image at build time so scans don't pay a
// network cost (and stay reproducible against a pinned ruleset).
func (*Semgrep) Run(ctx context.Context, args tool.Args) (tool.Result, error) {
	target, _ := args["target"].(string)
	if strings.TrimSpace(target) == "" {
		return tool.Result{}, errors.New("semgrep: missing required arg 'target'")
	}
	config := "p/security-audit"
	if c, ok := args["config"].(string); ok && c != "" {
		config = c
	}

	cmd := exec.CommandContext(ctx, "semgrep", "scan",
		"--config", config,
		"--config", "p/secrets",
		"--json",
		"--quiet",
		"--disable-version-check",
		"--metrics", "off",
		target,
	)
	stdout, err := cmd.Output()
	if err != nil {
		var ee *exec.ExitError
		if !errors.As(err, &ee) {
			return tool.Result{}, fmt.Errorf("semgrep: exec: %w", err)
		}
		// semgrep exits non-zero when findings are present; parse anyway.
	}
	return tool.Result{Output: string(stdout), Findings: parse(stdout)}, nil
}

// KnownArgs declares the recognized arg keys (tool.ArgSpec).
func (*Semgrep) KnownArgs() []string { return []string{"target", "config"} }

func init() { tool.Register(New()) }
