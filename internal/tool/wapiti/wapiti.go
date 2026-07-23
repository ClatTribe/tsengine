// Package wapiti wraps the Wapiti web-application vulnerability scanner as a tsengine Tool — the general
// active-scan breadth the web asset lacked. nuclei templates cover known CVEs/misconfigs, but the
// generic injection classes (SSTI/XXE/LFI/command-injection/CRLF/SSRF) rode nuclei templates ONLY; wapiti
// is a dedicated active fuzzer that crawls the app and injects payloads per parameter, closing the
// WAVSEP-breadth gap vs Burp/ZAP active-scan. Per §13 this WRAPS OSS rather than reimplementing a fuzzer.
//
// Registry-tier on the web asset (on-demand depth via the tool-replay API / dispatch, not every scan —
// active fuzzing is slow). The parser (parse) is pure + fully tested; the live scan is gated on the
// wapiti binary in the sandbox image (the honest tooling gate, like every wrapper). Registered via init().
package wapiti

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"

	"github.com/ClatTribe/tsengine/internal/tool"
	"github.com/ClatTribe/tsengine/pkg/types"
)

func init() { tool.Register(New()) }

// Wapiti is the tool.Tool implementation.
type Wapiti struct{}

// New constructs a Wapiti wrapper.
func New() *Wapiti { return &Wapiti{} }

func (*Wapiti) Name() string              { return "wapiti" }
func (*Wapiti) SandboxExecution() bool    { return true }
func (*Wapiti) MITRETechniques() []string { return []string{"T1190"} } // exploit public-facing application
func (*Wapiti) KnownArgs() []string       { return []string{"target", "modules", "depth"} }

// Run crawls + actively scans a web target and normalizes wapiti's JSON report into findings.
//
// Recognized args:
//
//	"target"  string — required, the base URL to scan
//	"modules" string — optional, wapiti module list (e.g. "sql,xss,exec"); default = wapiti's common set
//	"depth"   string — optional, crawl depth (wapiti -d)
//
// wapiti writes its JSON report to the -o path; we use a temp file (its stdout carries progress text, so
// it can't be parsed as JSON). A non-zero exit is not a wrapper error — findings are the point.
func (*Wapiti) Run(ctx context.Context, args tool.Args) (tool.Result, error) {
	target, _ := args["target"].(string)
	if strings.TrimSpace(target) == "" {
		return tool.Result{}, errors.New("wapiti: missing required arg 'target'")
	}
	out, err := os.CreateTemp("", "wapiti-*.json")
	if err != nil {
		return tool.Result{}, fmt.Errorf("wapiti: temp report: %w", err)
	}
	reportPath := out.Name()
	_ = out.Close()
	defer func() { _ = os.Remove(reportPath) }()

	argv := []string{"-u", target, "-f", "json", "-o", reportPath, "--flush-session"}
	if m, _ := args["modules"].(string); strings.TrimSpace(m) != "" {
		argv = append(argv, "-m", m)
	}
	if d, _ := args["depth"].(string); strings.TrimSpace(d) != "" {
		argv = append(argv, "-d", d)
	}
	cmd := exec.CommandContext(ctx, "wapiti", argv...)
	// Run for side effect (the report file); wapiti's exit code / stdout is not the report.
	if runErr := cmd.Run(); runErr != nil {
		var ee *exec.ExitError
		if !errors.As(runErr, &ee) {
			return tool.Result{}, fmt.Errorf("wapiti: exec: %w", runErr)
		}
		// non-zero exit (findings present / partial) — fall through to read the report.
	}
	blob, _ := os.ReadFile(reportPath)
	return tool.Result{Output: string(blob), Findings: parse(blob, target)}, nil
}

// wapitiReport is the slice of wapiti's JSON we rely on: a category → entries map.
type wapitiReport struct {
	Vulnerabilities map[string][]wapitiEntry `json:"vulnerabilities"`
}

type wapitiEntry struct {
	Method    string `json:"method"`
	Path      string `json:"path"`
	Info      string `json:"info"`
	Level     int    `json:"level"` // wapiti criticality 1..4 (higher = more severe)
	Parameter string `json:"parameter"`
	Module    string `json:"module"`
}

// parse normalizes wapiti's report into findings. Pure — the testable core. Sorted for determinism.
func parse(blob []byte, target string) []types.SandboxEmittedFinding {
	blob = bytes.TrimSpace(blob)
	if len(blob) == 0 || blob[0] != '{' {
		return nil
	}
	var rep wapitiReport
	if json.Unmarshal(blob, &rep) != nil {
		return nil
	}
	cats := make([]string, 0, len(rep.Vulnerabilities))
	for c := range rep.Vulnerabilities {
		cats = append(cats, c)
	}
	sort.Strings(cats)

	var out []types.SandboxEmittedFinding
	for _, category := range cats {
		entries := rep.Vulnerabilities[category]
		sort.SliceStable(entries, func(i, j int) bool {
			if entries[i].Path != entries[j].Path {
				return entries[i].Path < entries[j].Path
			}
			return entries[i].Parameter < entries[j].Parameter
		})
		for _, e := range entries {
			endpoint := e.Path
			if endpoint == "" {
				endpoint = target
			}
			if e.Parameter != "" {
				endpoint += " (param: " + e.Parameter + ")"
			}
			raw, _ := json.Marshal(e)
			title := category
			if e.Info != "" {
				title = category + ": " + firstLine(e.Info)
			}
			out = append(out, types.SandboxEmittedFinding{
				RuleID:          "wapiti::" + slug(category),
				Tool:            "wapiti",
				Severity:        severity(category, e.Level),
				CWE:             cweFor(category),
				Endpoint:        endpoint,
				Title:           title,
				Description:     e.Info,
				RawOutput:       raw,
				MITRETechniques: []string{"T1190"},
				ToolArgs:        map[string]string{"method": e.Method, "module": e.Module, "parameter": e.Parameter},
			})
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// seriousCategories are the injection/exec classes that are AT LEAST high regardless of wapiti's level.
var seriousCategories = map[string]bool{
	"sql injection": true, "blind sql injection": true, "command execution": true,
	"path traversal": true, "xml external entity": true, "server side request forgery": true,
	"cross site scripting": true, "crlf injection": true,
}

// severity maps a category + wapiti level (1..4) to our scale: a serious injection class floors at high;
// otherwise the level drives it (4→critical, 3→high, 2→medium, else low).
func severity(category string, level int) types.Severity {
	lc := strings.ToLower(strings.TrimSpace(category))
	base := types.SeverityLow
	switch {
	case level >= 4:
		base = types.SeverityCritical
	case level == 3:
		base = types.SeverityHigh
	case level == 2:
		base = types.SeverityMedium
	}
	if seriousCategories[lc] && sevRank(base) < sevRank(types.SeverityHigh) {
		return types.SeverityHigh
	}
	return base
}

func sevRank(s types.Severity) int {
	switch s {
	case types.SeverityCritical:
		return 4
	case types.SeverityHigh:
		return 3
	case types.SeverityMedium:
		return 2
	default:
		return 1
	}
}

// cweFor maps a wapiti category to its CWE(s). Unknown categories get no CWE (honest — never guessed).
func cweFor(category string) []string {
	switch strings.ToLower(strings.TrimSpace(category)) {
	case "sql injection", "blind sql injection":
		return []string{"CWE-89"}
	case "cross site scripting":
		return []string{"CWE-79"}
	case "command execution":
		return []string{"CWE-78"}
	case "path traversal":
		return []string{"CWE-22"}
	case "crlf injection":
		return []string{"CWE-93"}
	case "server side request forgery":
		return []string{"CWE-918"}
	case "xml external entity":
		return []string{"CWE-611"}
	case "open redirect":
		return []string{"CWE-601"}
	case "secure flag cookie":
		return []string{"CWE-614"}
	case "httponly flag cookie":
		return []string{"CWE-1004"}
	case "backup file":
		return []string{"CWE-530"}
	case "content security policy configuration":
		return []string{"CWE-693"}
	default:
		return nil
	}
}

func slug(category string) string {
	s := strings.ToLower(strings.TrimSpace(category))
	s = strings.ReplaceAll(s, " ", "-")
	return s
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}
