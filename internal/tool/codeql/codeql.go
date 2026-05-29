// Package codeql wraps GitHub CodeQL as a tsengine depth Tool for the
// repository asset. It fills the gap that caps semgrep: semgrep is
// pattern-match (a ~25% recall ceiling on OWASP-Benchmark); CodeQL does
// INTERPROCEDURAL TAINT/DATAFLOW — tracing untrusted input across function
// boundaries to a sink. It's slow + heavy (builds a DB), so the escalation
// engine fires it ONLY when semgrep already flagged an injection-class
// finding, and only for that language. Registers via init().
package codeql

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/ClatTribe/tsengine/internal/tool"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// CodeQL is the tool.Tool implementation.
type CodeQL struct{}

// New constructs a CodeQL wrapper.
func New() *CodeQL { return &CodeQL{} }

func (*CodeQL) Name() string              { return "codeql" }
func (*CodeQL) SandboxExecution() bool    { return true }
func (*CodeQL) MITRETechniques() []string { return []string{"T1059"} }

// KnownArgs declares the recognized arg keys (tool.ArgSpec).
func (*CodeQL) KnownArgs() []string { return []string{"target", "language"} }

// Run builds a CodeQL database and runs the security-extended suite.
//
//	"target"   string — required, the source root (workspace mount).
//	"language" string — required, codeql language (java/python/javascript/…).
func (*CodeQL) Run(ctx context.Context, args tool.Args) (tool.Result, error) {
	src, _ := args["target"].(string)
	lang, _ := args["language"].(string)
	src, lang = strings.TrimSpace(src), strings.TrimSpace(lang)
	if src == "" || lang == "" {
		return tool.Result{}, errors.New("codeql: 'target' and 'language' are required")
	}

	db, err := os.MkdirTemp("", "codeql-db-")
	if err != nil {
		return tool.Result{}, err
	}
	defer os.RemoveAll(db)
	sarif, err := os.CreateTemp("", "codeql-*.sarif")
	if err != nil {
		return tool.Result{}, err
	}
	sarifPath := sarif.Name()
	_ = sarif.Close()
	defer os.Remove(sarifPath)

	create := exec.CommandContext(ctx, "codeql", "database", "create", db,
		"--language="+lang, "--source-root="+src, "--overwrite")
	if out, err := create.CombinedOutput(); err != nil {
		var ee *exec.ExitError
		if !errors.As(err, &ee) {
			return tool.Result{Output: "codeql create: " + err.Error()}, nil
		}
		// DB build can fail on no-build languages / missing deps — degrade.
		return tool.Result{Output: "codeql database create failed:\n" + string(out)}, nil
	}

	analyze := exec.CommandContext(ctx, "codeql", "database", "analyze", db,
		lang+"-security-extended.qls",
		"--format=sarifv2.1.0", "--output="+sarifPath)
	combined, _ := analyze.CombinedOutput()

	blob, rerr := os.ReadFile(sarifPath) //nolint:gosec // temp file we created
	if rerr != nil || len(blob) == 0 {
		return tool.Result{Output: string(combined)}, nil
	}
	return tool.Result{Output: string(blob), Findings: parseSARIF(blob, lang)}, nil
}

// sarif mirrors the subset of SARIF 2.1.0 we read.
type sarif struct {
	Runs []struct {
		Results []struct {
			RuleID  string `json:"ruleId"`
			Message struct {
				Text string `json:"text"`
			} `json:"message"`
			Locations []struct {
				PhysicalLocation struct {
					ArtifactLocation struct {
						URI string `json:"uri"`
					} `json:"artifactLocation"`
					Region struct {
						StartLine int `json:"startLine"`
					} `json:"region"`
				} `json:"physicalLocation"`
			} `json:"locations"`
		} `json:"results"`
	} `json:"runs"`
}

func parseSARIF(blob []byte, lang string) []types.SandboxEmittedFinding {
	var s sarif
	if json.Unmarshal(blob, &s) != nil {
		return nil
	}
	var out []types.SandboxEmittedFinding
	for _, run := range s.Runs {
		for _, r := range run.Results {
			endpoint := lang
			if len(r.Locations) > 0 {
				loc := r.Locations[0].PhysicalLocation
				endpoint = fmt.Sprintf("%s:%d", loc.ArtifactLocation.URI, loc.Region.StartLine)
			}
			out = append(out, types.SandboxEmittedFinding{
				RuleID:          "codeql::" + r.RuleID,
				Tool:            "codeql",
				Severity:        types.SeverityHigh, // taint-flow hits are high-confidence
				Endpoint:        endpoint,
				Title:           r.Message.Text,
				Description:     "Interprocedural taint/dataflow finding (CodeQL security-extended).",
				MITRETechniques: []string{"T1059"},
				ToolArgs:        map[string]string{"language": lang},
			})
		}
	}
	return out
}

func init() { tool.Register(New()) }
