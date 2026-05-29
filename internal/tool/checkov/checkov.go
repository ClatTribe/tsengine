// Package checkov wraps Bridgecrew/Prisma checkov (IaC misconfiguration
// scanner) as a tsengine Tool for the repository asset. It covers the
// HashiCorp / cloud-native ecosystem (Terraform, CloudFormation,
// Kubernetes, Helm, ARM, Dockerfile, …) — the gap strix's own gap-analysis
// called "crippling" when it shipped a ~4-resource in-house IaC engine.
// Wrapping OSS instead of building in-house is exactly CLAUDE.md §13.
// Registers via init().
package checkov

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

// Checkov is the tool.Tool implementation.
type Checkov struct{}

// New constructs a Checkov wrapper.
func New() *Checkov { return &Checkov{} }

func (*Checkov) Name() string              { return "checkov" }
func (*Checkov) SandboxExecution() bool    { return true }
func (*Checkov) MITRETechniques() []string { return []string{"T1610", "T1078.004"} }

// KnownArgs declares the recognized arg keys (tool.ArgSpec).
func (*Checkov) KnownArgs() []string { return []string{"target"} }

// Run scans a directory tree for IaC misconfigurations.
//
//	"target" string — required, the path to scan (the workspace mount).
func (*Checkov) Run(ctx context.Context, args tool.Args) (tool.Result, error) {
	target, _ := args["target"].(string)
	if strings.TrimSpace(target) == "" {
		return tool.Result{}, errors.New("checkov: missing required arg 'target'")
	}
	cmd := exec.CommandContext(ctx, "checkov", "-d", target, "-o", "json", "--compact", "--quiet")
	stdout, err := cmd.Output()
	if err != nil {
		var ee *exec.ExitError
		if !errors.As(err, &ee) {
			return tool.Result{}, fmt.Errorf("checkov: exec: %w", err)
		}
		// checkov exits non-zero when checks fail — parse anyway.
	}
	return tool.Result{Output: string(stdout), Findings: parse(stdout)}, nil
}

// report mirrors checkov's JSON. The top level is an object for a single
// framework, or an array when multiple frameworks are detected — we accept
// both.
type report struct {
	Results struct {
		FailedChecks []failed `json:"failed_checks"`
	} `json:"results"`
}

type failed struct {
	CheckID   string `json:"check_id"`
	CheckName string `json:"check_name"`
	FilePath  string `json:"file_path"`
	Severity  string `json:"severity"`
	Resource  string `json:"resource"`
}

func parse(blob []byte) []types.SandboxEmittedFinding {
	blob = []byte(strings.TrimSpace(string(blob)))
	var reports []report
	if len(blob) > 0 && blob[0] == '[' {
		_ = json.Unmarshal(blob, &reports)
	} else {
		var single report
		if json.Unmarshal(blob, &single) == nil {
			reports = []report{single}
		}
	}
	var out []types.SandboxEmittedFinding
	for _, r := range reports {
		for _, f := range r.Results.FailedChecks {
			out = append(out, types.SandboxEmittedFinding{
				RuleID:          "checkov::" + f.CheckID,
				Tool:            "checkov",
				Severity:        severityFor(f.Severity),
				Endpoint:        f.FilePath + ":" + f.Resource,
				Title:           f.CheckName,
				MITRETechniques: []string{"T1610"},
				ToolArgs:        map[string]string{"check_id": f.CheckID},
			})
		}
	}
	return out
}

// severityFor maps checkov's severity (often empty on the free ruleset) to
// the tsengine scale; unknown/empty defaults to medium (a failed IaC check
// is a real misconfig, not info).
func severityFor(s string) types.Severity {
	switch strings.ToUpper(s) {
	case "CRITICAL":
		return types.SeverityCritical
	case "HIGH":
		return types.SeverityHigh
	case "LOW":
		return types.SeverityLow
	case "INFO":
		return types.SeverityInfo
	default:
		return types.SeverityMedium
	}
}

func init() { tool.Register(New()) }
