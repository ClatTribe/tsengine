// Package trufflehog wraps the trufflesecurity/trufflehog secret
// scanner. Used by the repository asset alongside gitleaks — trufflehog
// additionally VERIFIES secrets against live services, so the two
// corroborate (CLAUDE.md §11 hook 5). Registers via init().
package trufflehog

import (
	"bufio"
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

// Trufflehog is the tool.Tool implementation.
type Trufflehog struct{}

// New constructs a Trufflehog wrapper.
func New() *Trufflehog { return &Trufflehog{} }

func (*Trufflehog) Name() string              { return "trufflehog" }
func (*Trufflehog) SandboxExecution() bool    { return true }
func (*Trufflehog) MITRETechniques() []string { return []string{"T1552.001"} }

// Run scans a filesystem tree for secrets.
//
// Recognized args:
//
//	"target" string — required, path to the source tree (in-sandbox).
func (*Trufflehog) Run(ctx context.Context, args tool.Args) (tool.Result, error) {
	target, _ := args["target"].(string)
	if strings.TrimSpace(target) == "" {
		return tool.Result{}, errors.New("trufflehog: missing required arg 'target'")
	}
	cmd := exec.CommandContext(ctx, "trufflehog", "filesystem", target, "--json", "--no-update")
	stdout, err := cmd.Output()
	if err != nil {
		var ee *exec.ExitError
		if !errors.As(err, &ee) {
			return tool.Result{}, fmt.Errorf("trufflehog: exec: %w", err)
		}
	}
	return tool.Result{Output: string(stdout), Findings: parse(stdout)}, nil
}

type event struct {
	DetectorName   string `json:"DetectorName"`
	Verified       bool   `json:"Verified"`
	Raw            string `json:"Raw"`
	SourceMetadata struct {
		Data struct {
			Filesystem struct {
				File string `json:"file"`
				Line int    `json:"line"`
			} `json:"Filesystem"`
		} `json:"Data"`
	} `json:"SourceMetadata"`
}

func parse(blob []byte) []types.SandboxEmittedFinding {
	if len(blob) == 0 {
		return nil
	}
	var out []types.SandboxEmittedFinding
	sc := bufio.NewScanner(bytes.NewReader(blob))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 || line[0] != '{' {
			continue
		}
		var ev event
		if json.Unmarshal(line, &ev) != nil || ev.DetectorName == "" {
			continue
		}
		raw := make([]byte, len(line))
		copy(raw, line)
		fs := ev.SourceMetadata.Data.Filesystem
		endpoint := fs.File
		if fs.Line > 0 {
			endpoint = fmt.Sprintf("%s:%d", fs.File, fs.Line)
		}
		// A verified secret (confirmed live) is critical; an unverified
		// match is high.
		sev := types.SeverityHigh
		title := "Potential secret: " + ev.DetectorName
		if ev.Verified {
			sev = types.SeverityCritical
			title = "VERIFIED live secret: " + ev.DetectorName
		}
		out = append(out, types.SandboxEmittedFinding{
			RuleID:          "trufflehog::" + ev.DetectorName,
			Tool:            "trufflehog",
			Severity:        sev,
			CWE:             []string{"CWE-798"},
			Endpoint:        endpoint,
			Title:           title,
			RawOutput:       raw,
			MITRETechniques: []string{"T1552.001"},
			ToolArgs:        map[string]string{"detector": ev.DetectorName, "verified": fmt.Sprintf("%t", ev.Verified)},
		})
	}
	return out
}

// KnownArgs declares the recognized arg keys (tool.ArgSpec).
func (*Trufflehog) KnownArgs() []string { return []string{"target"} }

func init() { tool.Register(New()) }
