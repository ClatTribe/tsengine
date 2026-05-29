// Package scoutsuite wraps NCC Group's Scout Suite (multi-cloud CSPM) as a
// tsengine Tool for the cloud_account asset. It's the SECOND posture
// engine alongside prowler — two independent rule sets give the L1.5
// corroborator cross-source agreement (the cloud analog of trivy+grype).
// Registers via init().
//
// Like prowler, it needs cloud credentials forwarded via the sandbox env;
// without them it degrades to zero findings rather than crashing.
package scoutsuite

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/ClatTribe/tsengine/internal/tool"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// ScoutSuite is the tool.Tool implementation.
type ScoutSuite struct{}

// New constructs a ScoutSuite wrapper.
func New() *ScoutSuite { return &ScoutSuite{} }

func (*ScoutSuite) Name() string              { return "scoutsuite" }
func (*ScoutSuite) SandboxExecution() bool    { return true }
func (*ScoutSuite) MITRETechniques() []string { return []string{"T1078.004", "T1530", "T1580"} }

// KnownArgs declares the recognized arg keys (tool.ArgSpec).
func (*ScoutSuite) KnownArgs() []string { return []string{"target"} }

// Run executes scout against a provider. Recognized args:
//
//	"target" string — required, provider: "aws" | "gcp" | "azure".
func (*ScoutSuite) Run(ctx context.Context, args tool.Args) (tool.Result, error) {
	provider, _ := args["target"].(string)
	provider = strings.ToLower(strings.TrimSpace(provider))
	switch provider {
	case "aws", "gcp", "azure":
	case "":
		return tool.Result{}, errors.New("scoutsuite: missing required arg 'target' (aws|gcp|azure)")
	default:
		return tool.Result{}, fmt.Errorf("scoutsuite: unsupported provider %q", provider)
	}

	outDir, err := os.MkdirTemp("", "scout-")
	if err != nil {
		return tool.Result{}, err
	}
	defer os.RemoveAll(outDir)

	cmd := exec.CommandContext(ctx, "scout", provider,
		"--no-browser", "--force", "--report-dir", outDir)
	combined, _ := cmd.CombinedOutput()

	blob, readErr := readResults(outDir)
	if readErr != nil {
		// No results file → auth/availability failure. Degrade gracefully.
		return tool.Result{Output: string(combined)}, nil
	}
	return tool.Result{Output: string(blob), Findings: parse(blob)}, nil
}

// readResults locates Scout Suite's JS results file and strips the JS
// wrapper (`scoutsuite_results = {...}`) down to the JSON object.
func readResults(dir string) ([]byte, error) {
	var found string
	_ = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		if strings.HasPrefix(info.Name(), "scoutsuite_results") && strings.HasSuffix(info.Name(), ".js") {
			found = path
		}
		return nil
	})
	if found == "" {
		return nil, errors.New("scoutsuite: no results file produced")
	}
	raw, err := os.ReadFile(found) //nolint:gosec // temp dir we created
	if err != nil {
		return nil, err
	}
	return stripJSWrapper(raw), nil
}

// stripJSWrapper trims `scoutsuite_results =\n{ ... }` to the `{ ... }`.
func stripJSWrapper(raw []byte) []byte {
	s := string(raw)
	start := strings.Index(s, "{")
	end := strings.LastIndex(s, "}")
	if start < 0 || end <= start {
		return nil
	}
	return []byte(s[start : end+1])
}

// results mirrors the subset of Scout Suite's JSON we consume.
type results struct {
	Services map[string]struct {
		Findings map[string]struct {
			Description  string `json:"description"`
			Level        string `json:"level"`
			FlaggedItems int    `json:"flagged_items"`
			Rationale    string `json:"rationale"`
		} `json:"findings"`
	} `json:"services"`
}

func parse(blob []byte) []types.SandboxEmittedFinding {
	var r results
	if json.Unmarshal(blob, &r) != nil {
		return nil
	}
	var out []types.SandboxEmittedFinding
	for svc, s := range r.Services {
		for id, f := range s.Findings {
			if f.FlaggedItems <= 0 {
				continue // unflagged rule — nothing affected
			}
			out = append(out, types.SandboxEmittedFinding{
				RuleID:          fmt.Sprintf("scoutsuite::%s::%s", svc, id),
				Tool:            "scoutsuite",
				Severity:        severityFor(f.Level),
				Endpoint:        svc,
				Title:           f.Description,
				Description:     f.Rationale,
				MITRETechniques: []string{"T1078.004"},
				ToolArgs:        map[string]string{"flagged_items": fmt.Sprintf("%d", f.FlaggedItems)},
			})
		}
	}
	return out
}

func severityFor(level string) types.Severity {
	switch strings.ToLower(level) {
	case "danger":
		return types.SeverityHigh
	case "warning":
		return types.SeverityMedium
	default:
		return types.SeverityInfo
	}
}

func init() { tool.Register(New()) }
