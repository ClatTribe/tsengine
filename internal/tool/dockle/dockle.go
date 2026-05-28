// Package dockle wraps the goodwithtech/dockle container-image linter
// (CIS Docker Benchmark + best-practice checks). Used by the
// container_image asset. Registers via init().
package dockle

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

// Dockle is the tool.Tool implementation.
type Dockle struct{}

// New constructs a Dockle wrapper.
func New() *Dockle { return &Dockle{} }

func (*Dockle) Name() string              { return "dockle" }
func (*Dockle) SandboxExecution() bool    { return true }
func (*Dockle) MITRETechniques() []string { return []string{"T1610"} }

// Run lints a container image.
//
// Recognized args:
//
//	"target" string — required, the image ref.
func (*Dockle) Run(ctx context.Context, args tool.Args) (tool.Result, error) {
	target, _ := args["target"].(string)
	if strings.TrimSpace(target) == "" {
		return tool.Result{}, errors.New("dockle: missing required arg 'target'")
	}
	cmd := exec.CommandContext(ctx, "dockle", "-f", "json", "--exit-code", "0", target)
	stdout, err := cmd.Output()
	if err != nil {
		var ee *exec.ExitError
		if !errors.As(err, &ee) {
			return tool.Result{}, fmt.Errorf("dockle: exec: %w", err)
		}
	}
	return tool.Result{Output: string(stdout), Findings: parse(stdout, target)}, nil
}

type report struct {
	Details []detail `json:"details"`
}

type detail struct {
	Code   string   `json:"code"`
	Title  string   `json:"title"`
	Level  string   `json:"level"`
	Alerts []string `json:"alerts"`
}

func parse(blob []byte, target string) []types.SandboxEmittedFinding {
	if len(blob) == 0 {
		return nil
	}
	var r report
	if json.Unmarshal(blob, &r) != nil {
		return nil
	}
	out := make([]types.SandboxEmittedFinding, 0, len(r.Details))
	for _, d := range r.Details {
		sev := normalizeLevel(d.Level)
		// dockle emits PASS/IGNORE rows too; skip the non-findings.
		if sev == "" {
			continue
		}
		raw, _ := json.Marshal(d)
		out = append(out, types.SandboxEmittedFinding{
			RuleID:          "dockle::" + d.Code,
			Tool:            "dockle",
			Severity:        sev,
			Endpoint:        target,
			Title:           d.Title,
			Description:     strings.Join(d.Alerts, "; "),
			RawOutput:       raw,
			MITRETechniques: []string{"T1610"},
		})
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// normalizeLevel maps dockle's FATAL/WARN/INFO/SKIP/PASS to severities.
// Returns "" for non-findings (PASS/SKIP/IGNORE) so the caller drops them.
func normalizeLevel(l string) types.Severity {
	switch strings.ToUpper(strings.TrimSpace(l)) {
	case "FATAL":
		return types.SeverityHigh
	case "WARN":
		return types.SeverityMedium
	case "INFO":
		return types.SeverityInfo
	default: // PASS, SKIP, IGNORE
		return ""
	}
}

func init() { tool.Register(New()) }
