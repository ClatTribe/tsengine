// Package kics wraps KICS (Checkmarx "Keeping Infrastructure as Code Secure") as a tsengine depth Tool for the
// repository asset's registry tier. checkov is the IaC anchor; KICS is the on-demand DEEPER pass — its 2400+
// queries span Terraform, CloudFormation, Kubernetes, Ansible, Helm, Pulumi, Docker/Compose, and OpenAPI, so it
// catches IaC misconfigurations checkov's rule set can miss (the same anchor→registry depth pattern as
// semgrep→gosec/bandit for code). On-demand (registry-tier); registered via init().
package kics

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/ClatTribe/tsengine/internal/tool"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// KICS is the tool.Tool implementation.
type KICS struct{}

// New constructs a KICS wrapper.
func New() *KICS { return &KICS{} }

func (*KICS) Name() string              { return "kics" }
func (*KICS) SandboxExecution() bool    { return true }
func (*KICS) MITRETechniques() []string { return nil } // IaC misconfig — grounding is the query + file:line

// KnownArgs declares the recognized arg keys (tool.ArgSpec).
func (*KICS) KnownArgs() []string { return []string{"target"} }

// Run scans an IaC tree. Recognized args:
//
//	"target" string — required, the path to scan (workspace mount).
//
// KICS writes its JSON report to a directory (no stdout mode), so we point it at a temp dir and read
// results.json back — the same pattern as the prowler wrapper. A non-zero exit is expected when it finds
// issues, so we read the report regardless and only treat a missing file as a hard failure (graceful degrade).
func (*KICS) Run(ctx context.Context, args tool.Args) (tool.Result, error) {
	target, _ := args["target"].(string)
	if strings.TrimSpace(target) == "" {
		return tool.Result{}, errors.New("kics: missing required arg 'target'")
	}
	outDir, err := os.MkdirTemp("", "kics-")
	if err != nil {
		return tool.Result{}, err
	}
	defer os.RemoveAll(outDir)

	cmd := exec.CommandContext(ctx, "kics", "scan",
		"-p", target,
		"--report-formats", "json",
		"-o", outDir,
		"--output-name", "results",
		"--no-progress",
		"--silent",
	)
	combined, _ := cmd.CombinedOutput() // non-zero exit == "results found"; we read the file regardless

	blob, readErr := os.ReadFile(filepath.Join(outDir, "results.json")) //nolint:gosec // temp dir we created
	if readErr != nil {
		// No report — kics likely errored (bad path / unsupported tree). Degrade gracefully: surface stderr.
		return tool.Result{Output: string(combined)}, nil
	}
	return tool.Result{Output: string(blob), Findings: parse(blob)}, nil
}

// report mirrors the relevant slice of kics results.json.
type report struct {
	Queries []struct {
		QueryName string `json:"query_name"`
		QueryID   string `json:"query_id"`
		Severity  string `json:"severity"`
		Files     []struct {
			FileName string `json:"file_name"`
			Line     int    `json:"line"`
		} `json:"files"`
	} `json:"queries"`
}

func parse(blob []byte) []types.SandboxEmittedFinding {
	var r report
	if json.Unmarshal(blob, &r) != nil {
		return nil
	}
	var out []types.SandboxEmittedFinding
	for _, q := range r.Queries {
		rule := "kics::" + nz(q.QueryID, slug(q.QueryName))
		sev := severityFor(q.Severity)
		// kics groups every offending location under one query; emit one finding per file:line so the security
		// engineer sees each site (mirrors how the SAST wrappers emit per-location).
		if len(q.Files) == 0 {
			out = append(out, types.SandboxEmittedFinding{RuleID: rule, Tool: "kics", Severity: sev, Title: q.QueryName})
			continue
		}
		for _, f := range q.Files {
			endpoint := f.FileName
			if f.Line > 0 {
				endpoint = f.FileName + ":" + strconv.Itoa(f.Line)
			}
			out = append(out, types.SandboxEmittedFinding{
				RuleID:   rule,
				Tool:     "kics",
				Severity: sev,
				Endpoint: endpoint,
				Title:    q.QueryName,
			})
		}
	}
	return out
}

func severityFor(s string) types.Severity {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "CRITICAL":
		return types.SeverityCritical
	case "HIGH":
		return types.SeverityHigh
	case "MEDIUM":
		return types.SeverityMedium
	case "LOW":
		return types.SeverityLow
	default:
		return types.SeverityInfo
	}
}

func nz(s, dflt string) string {
	if strings.TrimSpace(s) == "" {
		return dflt
	}
	return s
}

// slug turns a query name into a stable rule-id fragment when no query_id is present.
func slug(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			return r
		}
		return '-'
	}, s)
	for strings.Contains(s, "--") {
		s = strings.ReplaceAll(s, "--", "-")
	}
	return strings.Trim(s, "-")
}

func init() { tool.Register(New()) }
