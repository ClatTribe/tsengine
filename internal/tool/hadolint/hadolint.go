// Package hadolint wraps the hadolint Dockerfile linter as a tsengine
// Tool (repository + container_image assets). It catches Dockerfile
// best-practice / security issues (root USER, unpinned base images, apt
// without --no-install-recommends, secrets in ENV, …). Registers via init().
package hadolint

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strings"

	"github.com/ClatTribe/tsengine/internal/tool"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// Hadolint is the tool.Tool implementation.
type Hadolint struct{}

// New constructs a Hadolint wrapper.
func New() *Hadolint { return &Hadolint{} }

func (*Hadolint) Name() string              { return "hadolint" }
func (*Hadolint) SandboxExecution() bool    { return true }
func (*Hadolint) MITRETechniques() []string { return []string{"T1610"} }

// KnownArgs declares the recognized arg keys (tool.ArgSpec).
func (*Hadolint) KnownArgs() []string { return []string{"target"} }

// Run lints a Dockerfile. Recognized args:
//
//	"target" string — required, path to the Dockerfile.
//
// A missing Dockerfile is not an error: the exec fails and we return zero
// findings (a repo may have no Dockerfile — graceful, not a crash).
func (*Hadolint) Run(ctx context.Context, args tool.Args) (tool.Result, error) {
	target, _ := args["target"].(string)
	if strings.TrimSpace(target) == "" {
		return tool.Result{}, errors.New("hadolint: missing required arg 'target'")
	}
	cmd := exec.CommandContext(ctx, "hadolint", "--format", "json", "--no-fail", target)
	stdout, err := cmd.Output()
	if err != nil {
		var ee *exec.ExitError
		if !errors.As(err, &ee) {
			// Binary missing or Dockerfile absent → no findings, no crash.
			return tool.Result{Output: "hadolint: " + err.Error()}, nil
		}
	}
	return tool.Result{Output: string(stdout), Findings: parse(stdout, target)}, nil
}

type issue struct {
	Line    int    `json:"line"`
	Code    string `json:"code"`
	Level   string `json:"level"`
	Message string `json:"message"`
}

func parse(blob []byte, target string) []types.SandboxEmittedFinding {
	var issues []issue
	if json.Unmarshal(blob, &issues) != nil {
		return nil
	}
	out := make([]types.SandboxEmittedFinding, 0, len(issues))
	for _, i := range issues {
		out = append(out, types.SandboxEmittedFinding{
			RuleID:          "hadolint::" + i.Code,
			Tool:            "hadolint",
			Severity:        severityFor(i.Level),
			Endpoint:        fmt.Sprintf("%s:%d", target, i.Line),
			Title:           i.Message,
			MITRETechniques: []string{"T1610"},
			ToolArgs:        map[string]string{"level": i.Level},
		})
	}
	return out
}

func severityFor(level string) types.Severity {
	switch strings.ToLower(level) {
	case "error":
		return types.SeverityHigh
	case "warning":
		return types.SeverityMedium
	case "info":
		return types.SeverityLow
	default:
		return types.SeverityInfo
	}
}

func init() { tool.Register(New()) }
