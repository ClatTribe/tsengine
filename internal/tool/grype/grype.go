// Package grype wraps the anchore/grype vulnerability scanner. It uses a
// different CVE database than trivy, so running both gives the L1.5
// corroborator cross-source agreement (CLAUDE.md §11 hook 5). Used by
// container_image (scans the image) and repository (scans the tree).
// Registers via init().
package grype

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

// Grype is the tool.Tool implementation.
type Grype struct{}

// New constructs a Grype wrapper.
func New() *Grype { return &Grype{} }

func (*Grype) Name() string              { return "grype" }
func (*Grype) SandboxExecution() bool    { return true }
func (*Grype) MITRETechniques() []string { return []string{"T1195.002"} }

// Run scans an image ref or directory.
//
// Recognized args:
//
//	"target" string — required. An image ref ("nginx:1.14") or a grype
//	                  source string ("dir:/workspace"). The Handler picks
//	                  the right form per asset.
func (*Grype) Run(ctx context.Context, args tool.Args) (tool.Result, error) {
	target, _ := args["target"].(string)
	if strings.TrimSpace(target) == "" {
		return tool.Result{}, errors.New("grype: missing required arg 'target'")
	}
	cmd := exec.CommandContext(ctx, "grype", target, "-o", "json", "-q")
	stdout, err := cmd.Output()
	if err != nil {
		var ee *exec.ExitError
		if !errors.As(err, &ee) {
			return tool.Result{}, fmt.Errorf("grype: exec: %w", err)
		}
	}
	return tool.Result{Output: string(stdout), Findings: parse(stdout, target)}, nil
}

type report struct {
	Matches []match `json:"matches"`
}

type match struct {
	Vulnerability struct {
		ID         string   `json:"id"`
		Severity   string   `json:"severity"`
		Description string  `json:"description"`
		URLs       []string `json:"urls"`
	} `json:"vulnerability"`
	Artifact struct {
		Name    string `json:"name"`
		Version string `json:"version"`
		Type    string `json:"type"`
	} `json:"artifact"`
}

func parse(blob []byte, target string) []types.SandboxEmittedFinding {
	if len(blob) == 0 {
		return nil
	}
	var r report
	if json.Unmarshal(blob, &r) != nil {
		return nil
	}
	out := make([]types.SandboxEmittedFinding, 0, len(r.Matches))
	for _, m := range r.Matches {
		raw, _ := json.Marshal(m)
		// Endpoint identifies the affected package so distinct
		// package-CVE pairs don't collapse in cross_tool_merge.
		endpoint := target
		if m.Artifact.Name != "" {
			endpoint = fmt.Sprintf("%s [%s@%s]", target, m.Artifact.Name, m.Artifact.Version)
		}
		out = append(out, types.SandboxEmittedFinding{
			RuleID:          "grype::" + m.Vulnerability.ID,
			Tool:            "grype",
			Severity:        normalizeSeverity(m.Vulnerability.Severity),
			Endpoint:        endpoint,
			Title:           fmt.Sprintf("%s in %s", m.Vulnerability.ID, m.Artifact.Name),
			Description:     m.Vulnerability.Description,
			RawOutput:       raw,
			MITRETechniques: []string{"T1195.002"},
			ToolArgs:        map[string]string{"pkg": m.Artifact.Name, "installed_version": m.Artifact.Version},
		})
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func normalizeSeverity(s string) types.Severity {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return types.SeverityCritical
	case "high":
		return types.SeverityHigh
	case "medium":
		return types.SeverityMedium
	case "low":
		return types.SeverityLow
	case "negligible", "unknown", "":
		return types.SeverityInfo
	default:
		return types.SeverityInfo
	}
}

// KnownArgs declares the recognized arg keys (tool.ArgSpec).
func (*Grype) KnownArgs() []string { return []string{"target"} }

func init() { tool.Register(New()) }
