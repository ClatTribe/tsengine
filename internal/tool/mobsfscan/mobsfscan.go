// Package mobsfscan wraps MobSF's mobsfscan (mobile SAST for Android/iOS)
// as a tsengine depth Tool for the repository asset. It fills a gap
// semgrep's general packs miss: mobile-specific insecure patterns
// (insecure WebView, hardcoded keys in smali/plist, weak crypto, exported
// components, ATS misconfig). The escalation engine fires it only when the
// repo looks mobile (a finding in a mobile manifest/source). Registers via
// init().
package mobsfscan

import (
	"context"
	"encoding/json"
	"errors"
	"os/exec"
	"strings"

	"github.com/ClatTribe/tsengine/internal/tool"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// MobSFScan is the tool.Tool implementation.
type MobSFScan struct{}

// New constructs a MobSFScan wrapper.
func New() *MobSFScan { return &MobSFScan{} }

func (*MobSFScan) Name() string              { return "mobsfscan" }
func (*MobSFScan) SandboxExecution() bool    { return true }
func (*MobSFScan) MITRETechniques() []string { return []string{"T1444"} }

// KnownArgs declares the recognized arg keys (tool.ArgSpec).
func (*MobSFScan) KnownArgs() []string { return []string{"target"} }

// Run scans a mobile source tree. Recognized args:
//
//	"target" string — required, the path to scan (workspace mount).
func (*MobSFScan) Run(ctx context.Context, args tool.Args) (tool.Result, error) {
	target, _ := args["target"].(string)
	if strings.TrimSpace(target) == "" {
		return tool.Result{}, errors.New("mobsfscan: missing required arg 'target'")
	}
	cmd := exec.CommandContext(ctx, "mobsfscan", "--json", target)
	out, err := cmd.CombinedOutput()
	if err != nil {
		var ee *exec.ExitError
		if !errors.As(err, &ee) {
			return tool.Result{Output: "mobsfscan: " + err.Error()}, nil
		}
	}
	return tool.Result{Output: string(out), Findings: parse(out)}, nil
}

// report mirrors mobsfscan's JSON: results keyed by rule id.
type report struct {
	Results map[string]struct {
		Metadata struct {
			Severity    string `json:"severity"`
			Description string `json:"description"`
			CWE         string `json:"cwe"`
		} `json:"metadata"`
		Files []struct {
			FilePath  string `json:"file_path"`
			MatchLine []int  `json:"match_lines"`
		} `json:"files"`
	} `json:"results"`
}

func parse(blob []byte) []types.SandboxEmittedFinding {
	var r report
	if json.Unmarshal(blob, &r) != nil {
		return nil
	}
	var out []types.SandboxEmittedFinding
	for ruleID, res := range r.Results {
		endpoint := "mobile"
		if len(res.Files) > 0 {
			endpoint = res.Files[0].FilePath
		}
		f := types.SandboxEmittedFinding{
			RuleID:          "mobsfscan::" + ruleID,
			Tool:            "mobsfscan",
			Severity:        severityFor(res.Metadata.Severity),
			Endpoint:        endpoint,
			Title:           res.Metadata.Description,
			MITRETechniques: []string{"T1444"},
		}
		if c := normalizeCWE(res.Metadata.CWE); c != "" {
			f.CWE = []string{c}
		}
		out = append(out, f)
	}
	return out
}

func severityFor(s string) types.Severity {
	switch strings.ToUpper(s) {
	case "ERROR", "HIGH":
		return types.SeverityHigh
	case "WARNING", "MEDIUM":
		return types.SeverityMedium
	case "INFO":
		return types.SeverityInfo
	default:
		return types.SeverityLow
	}
}

// normalizeCWE pulls a "CWE-89"-style id out of mobsfscan's "cwe" string
// (e.g. "CWE-89: SQL Injection").
func normalizeCWE(s string) string {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(strings.ToUpper(s), "CWE-") {
		return ""
	}
	if i := strings.IndexAny(s, ": "); i > 0 {
		return s[:i]
	}
	return s
}

func init() { tool.Register(New()) }
