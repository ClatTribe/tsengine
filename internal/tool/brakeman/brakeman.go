// Package brakeman wraps Brakeman, the leading Ruby-on-Rails static analysis security scanner, as a
// tsengine Tool — the Rails-specific SAST depth the repository asset lacked. semgrep's generic Ruby packs
// catch some patterns, but Brakeman understands Rails idioms (mass-assignment, unsafe finders, CSRF-skip,
// unscoped queries, dangerous send/eval, SSRF via open-uri) that pattern SAST misses — closing the
// non-Go/Python language-depth gap (only CodeQL covered deep taint before, and it's registry-gated). Per
// §13 this WRAPS OSS, not an in-house analyzer.
//
// Registry-tier on the repository asset (fires on-demand / when the tree is a Rails project). The parser
// is pure + tested; the live scan is gated on the brakeman gem in the sandbox image (Ruby is already there
// for wpscan). Registered via init(). Brakeman's JSON warnings carry cwe_id directly, so the CWE mapping
// is grounded in the tool's own output — never guessed.
package brakeman

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"sort"
	"strings"

	"github.com/ClatTribe/tsengine/internal/tool"
	"github.com/ClatTribe/tsengine/pkg/types"
)

func init() { tool.Register(New()) }

// Brakeman is the tool.Tool implementation.
type Brakeman struct{}

// New constructs a Brakeman wrapper.
func New() *Brakeman { return &Brakeman{} }

func (*Brakeman) Name() string              { return "brakeman" }
func (*Brakeman) SandboxExecution() bool    { return true }
func (*Brakeman) MITRETechniques() []string { return []string{"T1190"} } // exploit public-facing application
func (*Brakeman) KnownArgs() []string       { return []string{"target"} }

// Run runs Brakeman over a Rails source tree and normalizes its JSON warnings into findings.
//
// Recognized args:
//
//	"target" string — required, path to the Rails app root (in-sandbox)
//
// Brakeman prints its JSON report to stdout with `-f json`; it exits non-zero when it finds warnings,
// which is NOT a wrapper error (the warnings are the point — mirrors gitleaks/wapiti). --no-pager/-q keep
// stdout clean JSON.
func (*Brakeman) Run(ctx context.Context, args tool.Args) (tool.Result, error) {
	target, _ := args["target"].(string)
	if strings.TrimSpace(target) == "" {
		return tool.Result{}, errors.New("brakeman: missing required arg 'target'")
	}
	cmd := exec.CommandContext(ctx, "brakeman", "-f", "json", "-q", "--no-progress", target)
	stdout, err := cmd.Output()
	if err != nil {
		var ee *exec.ExitError
		if !errors.As(err, &ee) {
			return tool.Result{}, fmt.Errorf("brakeman: exec: %w", err)
		}
		// non-zero exit with JSON on stdout = warnings found; fall through to parse.
	}
	return tool.Result{Output: string(stdout), Findings: parse(stdout, target)}, nil
}

// brakemanReport is the slice of Brakeman's JSON we rely on.
type brakemanReport struct {
	Warnings []brakemanWarning `json:"warnings"`
}

type brakemanWarning struct {
	WarningType string `json:"warning_type"`
	Message     string `json:"message"`
	File        string `json:"file"`
	Line        int    `json:"line"`
	Confidence  string `json:"confidence"` // High | Medium | Weak
	CWEID       []int  `json:"cwe_id"`
	Code        string `json:"code"`
}

// parse normalizes Brakeman's report into findings. Pure — the testable core. CWE comes from Brakeman's
// own cwe_id (grounded); severity from its confidence (the tool's FP-likelihood signal). Sorted.
func parse(blob []byte, target string) []types.SandboxEmittedFinding {
	blob = bytes.TrimSpace(blob)
	if len(blob) == 0 || blob[0] != '{' {
		return nil
	}
	var rep brakemanReport
	if json.Unmarshal(blob, &rep) != nil {
		return nil
	}
	ws := rep.Warnings
	sort.SliceStable(ws, func(i, j int) bool {
		if ws[i].File != ws[j].File {
			return ws[i].File < ws[j].File
		}
		if ws[i].Line != ws[j].Line {
			return ws[i].Line < ws[j].Line
		}
		return ws[i].WarningType < ws[j].WarningType
	})
	out := make([]types.SandboxEmittedFinding, 0, len(ws))
	for _, w := range ws {
		endpoint := w.File
		if endpoint == "" {
			endpoint = target
		}
		if w.Line > 0 {
			endpoint = fmt.Sprintf("%s:%d", endpoint, w.Line)
		}
		raw, _ := json.Marshal(w)
		out = append(out, types.SandboxEmittedFinding{
			RuleID:          "brakeman::" + slug(w.WarningType),
			Tool:            "brakeman",
			Severity:        severityOf(w.Confidence),
			CWE:             cweStrings(w.CWEID),
			Endpoint:        endpoint,
			Title:           strings.TrimSpace(w.WarningType + ": " + firstLine(w.Message)),
			Description:     w.Message,
			RawOutput:       raw,
			MITRETechniques: []string{"T1190"},
			ToolArgs:        map[string]string{"confidence": w.Confidence, "warning_type": w.WarningType},
		})
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// severityOf maps Brakeman confidence to our scale (confidence IS Brakeman's quality signal): High→high,
// Medium→medium, Weak→low, unknown→medium.
func severityOf(confidence string) types.Severity {
	switch strings.ToLower(strings.TrimSpace(confidence)) {
	case "high":
		return types.SeverityHigh
	case "weak":
		return types.SeverityLow
	case "medium":
		return types.SeverityMedium
	default:
		return types.SeverityMedium
	}
}

func cweStrings(ids []int) []string {
	if len(ids) == 0 {
		return nil
	}
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		if id > 0 {
			out = append(out, fmt.Sprintf("CWE-%d", id))
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func slug(s string) string {
	return strings.ReplaceAll(strings.ToLower(strings.TrimSpace(s)), " ", "-")
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}
