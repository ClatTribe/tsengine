// Package modelscan wraps Protect AI's `modelscan` as a tsengine Tool — the ML/data supply-chain
// scanner. It statically inspects serialized model + dataset artifacts (pickle/PyTorch/joblib/dill,
// TensorFlow, Keras, numpy) for the unsafe-deserialization operators that execute arbitrary code the
// moment the artifact is LOADED. This is the exact entry vector of the OpenAI×Hugging Face incident:
// a malicious dataset whose loader ran code on a processing worker.
//
// Per §13 this WRAPS an OSS scanner (modelscan) rather than reimplementing pickle disassembly in-house.
// The wrapper's parse() — the output normaliser — is pure + fully tested; the live scan is gated on the
// modelscan binary in the sandbox image (the honest credential/tooling gate, like every other wrapper).
// Registered via init(); used by the repository asset (an artifact in a connected repo).
package modelscan

import (
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

func init() { tool.Register(New()) }

// Modelscan is the tool.Tool implementation.
type Modelscan struct{}

// New constructs a Modelscan wrapper.
func New() *Modelscan { return &Modelscan{} }

func (*Modelscan) Name() string           { return "modelscan" }
func (*Modelscan) SandboxExecution() bool { return true }
func (*Modelscan) MITRETechniques() []string {
	// T1195.002 supply-chain compromise; T1059 command/scripting via the deserialization gadget.
	return []string{"T1195.002", "T1059"}
}

// KnownArgs declares the recognized arg keys (tool.ArgSpec).
func (*Modelscan) KnownArgs() []string { return []string{"target"} }

// Run scans a path (a model/dataset artifact or a directory of them) for unsafe operators.
//
// Recognized args:
//
//	"target" string — required, path to the artifact or directory (in-sandbox)
//
// modelscan emits JSON to stdout via `-r json -o /dev/stdout`. It exits non-zero when it finds issues,
// which is NOT a wrapper error — the findings are the point (mirrors gitleaks' --exit-code handling).
func (*Modelscan) Run(ctx context.Context, args tool.Args) (tool.Result, error) {
	target, _ := args["target"].(string)
	if strings.TrimSpace(target) == "" {
		return tool.Result{}, errors.New("modelscan: missing required arg 'target'")
	}
	cmd := exec.CommandContext(ctx, "modelscan", "-p", target, "-r", "json", "-o", "/dev/stdout")
	stdout, err := cmd.Output()
	if err != nil {
		var ee *exec.ExitError
		if !errors.As(err, &ee) {
			return tool.Result{}, fmt.Errorf("modelscan: exec: %w", err)
		}
		// non-zero exit with JSON on stdout = issues found; fall through to parse.
	}
	return tool.Result{Output: string(stdout), Findings: parse(stdout, target)}, nil
}

// modelscanReport is the slice of modelscan's JSON we rely on.
type modelscanReport struct {
	Issues []modelscanIssue `json:"issues"`
}

type modelscanIssue struct {
	Description string `json:"description"`
	Operator    string `json:"operator"` // the dangerous op, e.g. "posix.system", "builtins.eval"
	Module      string `json:"module"`   // the imported module, e.g. "os", "subprocess"
	Source      string `json:"source"`   // the artifact path (+ optional :entry for a zip member)
	Scanner     string `json:"scanner"`
	Severity    string `json:"severity"` // CRITICAL | HIGH | MEDIUM | LOW
}

// parse normalises modelscan's report into findings. Pure — the testable core. An unsafe-deserialization
// operator in a model/dataset artifact is CWE-502 (deserialization of untrusted data).
func parse(blob []byte, target string) []types.SandboxEmittedFinding {
	blob = bytes.TrimSpace(blob)
	if len(blob) == 0 || blob[0] != '{' {
		return nil
	}
	var rep modelscanReport
	if json.Unmarshal(blob, &rep) != nil {
		return nil
	}
	out := make([]types.SandboxEmittedFinding, 0, len(rep.Issues))
	for _, is := range rep.Issues {
		raw, _ := json.Marshal(is)
		endpoint := is.Source
		if endpoint == "" {
			endpoint = target
		}
		title := is.Description
		if title == "" {
			title = fmt.Sprintf("Unsafe operator %s in a model/dataset artifact", is.Operator)
		}
		out = append(out, types.SandboxEmittedFinding{
			RuleID:   "modelscan::" + ruleSlug(is),
			Tool:     "modelscan",
			Severity: mapSeverity(is.Severity),
			CWE:      []string{"CWE-502"}, // deserialization of untrusted data
			Endpoint: endpoint,
			Title:    title,
			Description: fmt.Sprintf("modelscan flagged operator %q (module %q) — loading this artifact would execute code. Do not load untrusted models/datasets; use a safe format (safetensors) or a sandboxed loader.",
				is.Operator, is.Module),
			RawOutput:       raw,
			MITRETechniques: []string{"T1195.002", "T1059"},
			ToolArgs:        map[string]string{"operator": is.Operator, "module": is.Module, "scanner": is.Scanner},
		})
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// ruleSlug builds a stable rule id from the operator/module (e.g. "unsafe-op::posix.system").
func ruleSlug(is modelscanIssue) string {
	op := strings.TrimSpace(is.Operator)
	if op == "" {
		op = strings.TrimSpace(is.Module)
	}
	if op == "" {
		op = "unsafe-operator"
	}
	return "unsafe-op::" + op
}

// mapSeverity maps modelscan's severity to ours; an unknown/blank severity is HIGH (an unsafe operator
// is dangerous by default — never silently downgraded to info).
func mapSeverity(s string) types.Severity {
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
		return types.SeverityHigh
	}
}
