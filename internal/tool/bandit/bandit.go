// Package bandit wraps Bandit (PyCQA/bandit), the Python security SAST, as a tsengine depth Tool for the
// repository asset's registry tier. It complements semgrep's generic python packs with Bandit's curated
// Python-specific checks: subprocess shell=True / os.system (B602/B605 command injection), yaml.load &
// pickle / marshal deserialization (B506/B301), assert in production (B101), hardcoded passwords (B105/B106),
// weak crypto (B303/B324 MD5), and SSL/cert verification disabled (B501). On-demand (registry-tier); init().
package bandit

import (
	"context"
	"encoding/json"
	"errors"
	"os/exec"
	"strconv"
	"strings"

	"github.com/ClatTribe/tsengine/internal/tool"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// Bandit is the tool.Tool implementation.
type Bandit struct{}

// New constructs a Bandit wrapper.
func New() *Bandit { return &Bandit{} }

func (*Bandit) Name() string              { return "bandit" }
func (*Bandit) SandboxExecution() bool    { return true }
func (*Bandit) MITRETechniques() []string { return nil } // SAST — grounding is the per-finding CWE, not ATT&CK

// KnownArgs declares the recognized arg keys (tool.ArgSpec).
func (*Bandit) KnownArgs() []string { return []string{"target"} }

// Run scans a Python source tree. Recognized args:
//
//	"target" string — required, the path to scan (workspace mount).
func (*Bandit) Run(ctx context.Context, args tool.Args) (tool.Result, error) {
	target, _ := args["target"].(string)
	if strings.TrimSpace(target) == "" {
		return tool.Result{}, errors.New("bandit: missing required arg 'target'")
	}
	// -r recursive, -f json to stdout, -q quiet. Bandit exits 1 when it finds issues, so a non-ExitError is
	// the only hard failure.
	cmd := exec.CommandContext(ctx, "bandit", "-r", "-f", "json", "-q", target)
	out, err := cmd.CombinedOutput()
	if err != nil {
		var ee *exec.ExitError
		if !errors.As(err, &ee) {
			return tool.Result{Output: "bandit: " + err.Error()}, nil
		}
	}
	return tool.Result{Output: string(out), Findings: parse(out)}, nil
}

// report mirrors bandit's -f json output. issue_cwe.id is an integer.
type report struct {
	Results []struct {
		Filename   string `json:"filename"`
		Severity   string `json:"issue_severity"`
		Confidence string `json:"issue_confidence"`
		CWE        struct {
			ID int `json:"id"`
		} `json:"issue_cwe"`
		Text   string `json:"issue_text"`
		TestID string `json:"test_id"`
		Line   int    `json:"line_number"`
	} `json:"results"`
}

func parse(blob []byte) []types.SandboxEmittedFinding {
	var r report
	if json.Unmarshal(blob, &r) != nil {
		return nil
	}
	var out []types.SandboxEmittedFinding
	for _, res := range r.Results {
		endpoint := res.Filename
		if res.Line > 0 {
			endpoint = res.Filename + ":" + strconv.Itoa(res.Line)
		}
		f := types.SandboxEmittedFinding{
			RuleID:      "bandit::" + res.TestID,
			Tool:        "bandit",
			Severity:    severityFor(res.Severity, res.Confidence),
			Endpoint:    endpoint,
			Title:       res.Text,
			Description: res.Text + " (bandit " + res.TestID + ", confidence " + res.Confidence + ")",
		}
		if res.CWE.ID > 0 {
			f.CWE = []string{"CWE-" + strconv.Itoa(res.CWE.ID)}
		}
		out = append(out, f)
	}
	return out
}

// severityFor maps bandit's severity, capping a LOW-confidence high/critical at medium — bandit's
// low-confidence highs are a known false-positive source, so we don't raise a high alarm without corroboration
// (the L1.5 corroborator/confidence hooks can still upgrade it). Faithful to the tool's two signals (§10).
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

func init() { tool.Register(New()) }
