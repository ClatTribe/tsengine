// Package gosec wraps gosec (securego/gosec), the Go-specific security SAST, as a tsengine depth Tool for the
// repository asset's registry tier. It complements semgrep's generic packs with Go-idiomatic rules the generic
// engine misses: weak crypto (G401/G501 MD5/DES), hardcoded credentials (G101), SQL string-building (G201/G202),
// unhandled errors on security calls (G104), unsafe/pointer use (G103), tainted file paths (G304), and bind-to-all
// (G102). On-demand (registry-tier); registered via init().
package gosec

import (
	"context"
	"encoding/json"
	"errors"
	"os/exec"
	"strings"

	"github.com/ClatTribe/tsengine/internal/tool"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// Gosec is the tool.Tool implementation.
type Gosec struct{}

// New constructs a Gosec wrapper.
func New() *Gosec { return &Gosec{} }

func (*Gosec) Name() string              { return "gosec" }
func (*Gosec) SandboxExecution() bool    { return true }
func (*Gosec) MITRETechniques() []string { return nil } // SAST — grounding is the per-finding CWE, not ATT&CK

// KnownArgs declares the recognized arg keys (tool.ArgSpec).
func (*Gosec) KnownArgs() []string { return []string{"target"} }

// Run scans a Go source tree. Recognized args:
//
//	"target" string — required, the path to scan (workspace mount).
func (*Gosec) Run(ctx context.Context, args tool.Args) (tool.Result, error) {
	target, _ := args["target"].(string)
	if strings.TrimSpace(target) == "" {
		return tool.Result{}, errors.New("gosec: missing required arg 'target'")
	}
	// JSON to stdout, quiet, and -no-fail so a "found issues" run exits 0. The recursive package pattern
	// scans the whole mounted tree.
	cmd := exec.CommandContext(ctx, "gosec", "-fmt=json", "-quiet", "-no-fail", strings.TrimRight(target, "/")+"/...")
	out, err := cmd.CombinedOutput()
	if err != nil {
		var ee *exec.ExitError
		if !errors.As(err, &ee) {
			return tool.Result{Output: "gosec: " + err.Error()}, nil
		}
	}
	return tool.Result{Output: string(out), Findings: parse(out)}, nil
}

// report mirrors gosec's -fmt=json output.
type report struct {
	Issues []struct {
		Severity   string `json:"severity"`
		Confidence string `json:"confidence"`
		CWE        struct {
			ID string `json:"id"`
		} `json:"cwe"`
		RuleID  string `json:"rule_id"`
		Details string `json:"details"`
		File    string `json:"file"`
		Line    string `json:"line"`
	} `json:"Issues"`
}

func parse(blob []byte) []types.SandboxEmittedFinding {
	var r report
	if json.Unmarshal(blob, &r) != nil {
		return nil
	}
	var out []types.SandboxEmittedFinding
	for _, iss := range r.Issues {
		endpoint := iss.File
		if iss.Line != "" {
			endpoint = iss.File + ":" + iss.Line
		}
		f := types.SandboxEmittedFinding{
			RuleID:      "gosec::" + iss.RuleID,
			Tool:        "gosec",
			Severity:    severityFor(iss.Severity, iss.Confidence),
			Endpoint:    endpoint,
			Title:       iss.Details,
			Description: iss.Details + " (gosec " + iss.RuleID + ", confidence " + iss.Confidence + ")",
		}
		if c := normalizeCWE(iss.CWE.ID); c != "" {
			f.CWE = []string{c}
		}
		out = append(out, f)
	}
	return out
}

// severityFor maps gosec's severity, capping a LOW-confidence finding at medium — gosec's low-confidence highs
// are a common false-positive source, so we don't raise a high/critical alarm without corroboration (the L1.5
// corroborator/confidence hooks can still upgrade it later). Grounded: faithful to the tool's own two signals.
func severityFor(severity, confidence string) types.Severity {
	sev := rank(severity)
	if strings.EqualFold(confidence, "LOW") && sev.Rank() > types.SeverityMedium.Rank() {
		return types.SeverityMedium
	}
	return sev
}

func rank(s string) types.Severity {
	switch strings.ToUpper(strings.TrimSpace(s)) {
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

// normalizeCWE turns gosec's bare numeric cwe id ("89") into the canonical "CWE-89".
func normalizeCWE(id string) string {
	id = strings.TrimSpace(id)
	if id == "" {
		return ""
	}
	if strings.HasPrefix(strings.ToUpper(id), "CWE-") {
		return id
	}
	return "CWE-" + id
}

func init() { tool.Register(New()) }
