// Package gitleaks wraps the gitleaks secret scanner as a tsengine Tool.
// Used by the repository asset. Registers via init().
package gitleaks

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strings"

	"github.com/ClatTribe/tsengine/internal/tool"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// Gitleaks is the tool.Tool implementation.
type Gitleaks struct{}

// New constructs a Gitleaks wrapper.
func New() *Gitleaks { return &Gitleaks{} }

func (*Gitleaks) Name() string              { return "gitleaks" }
func (*Gitleaks) SandboxExecution() bool    { return true }
func (*Gitleaks) MITRETechniques() []string { return []string{"T1552.001"} }

// Run scans a directory for committed secrets.
//
// Recognized args:
//
//	"target" string — required, path to the source tree (in-sandbox)
//
// gitleaks emits a JSON array of findings to stdout via
// `--report-path /dev/stdout`. --no-git scans the working tree (the
// repo is bind-mounted read-only, often without .git history).
func (*Gitleaks) Run(ctx context.Context, args tool.Args) (tool.Result, error) {
	target, _ := args["target"].(string)
	if strings.TrimSpace(target) == "" {
		return tool.Result{}, errors.New("gitleaks: missing required arg 'target'")
	}
	cmd := exec.CommandContext(ctx, "gitleaks", "detect",
		"--source", target,
		"--no-git",
		"--report-format", "json",
		"--report-path", "/dev/stdout",
		"--exit-code", "0",
	)
	stdout, err := cmd.Output()
	if err != nil {
		var ee *exec.ExitError
		if !errors.As(err, &ee) {
			return tool.Result{}, fmt.Errorf("gitleaks: exec: %w", err)
		}
	}
	return tool.Result{Output: string(stdout), Findings: parse(stdout, target)}, nil
}

type leak struct {
	RuleID      string `json:"RuleID"`
	Description string `json:"Description"`
	File        string `json:"File"`
	StartLine   int    `json:"StartLine"`
	EndLine     int    `json:"EndLine"`
	Match       string `json:"Match"`
	Secret      string `json:"Secret"`
}

func parse(blob []byte, target string) []types.SandboxEmittedFinding {
	blob = bytes.TrimSpace(blob)
	if len(blob) == 0 || blob[0] != '[' {
		return nil
	}
	var leaks []leak
	if json.Unmarshal(blob, &leaks) != nil {
		return nil
	}
	out := make([]types.SandboxEmittedFinding, 0, len(leaks))
	for _, l := range leaks {
		raw, _ := json.Marshal(l)
		endpoint := l.File
		if l.StartLine > 0 {
			endpoint = fmt.Sprintf("%s:%d", l.File, l.StartLine)
		}
		out = append(out, types.SandboxEmittedFinding{
			RuleID:          "gitleaks::" + l.RuleID,
			Tool:            "gitleaks",
			Severity:        types.SeverityHigh, // a live secret is high by default
			CWE:             []string{"CWE-798"},
			Endpoint:        endpoint,
			Title:           firstNonEmpty(l.Description, "Hardcoded secret: "+l.RuleID),
			RawOutput:       raw,
			MITRETechniques: []string{"T1552.001"},
			ToolArgs:        map[string]string{"rule": l.RuleID, "file": l.File},
		})
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func firstNonEmpty(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return a
	}
	return b
}

func init() { tool.Register(New()) }
