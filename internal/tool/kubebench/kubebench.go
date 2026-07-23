// Package kubebench wraps Aqua Security's kube-bench — the CIS Kubernetes Benchmark auditor — as a
// tsengine Tool. This is the KSPM (Kubernetes Security Posture Management) gap: checkov/kics already scan
// k8s MANIFESTS statically, but nothing audited a RUNNING cluster's CIS posture (API-server flags, kubelet
// config, etcd encryption-at-rest, RBAC, admission control) — the distinct runtime k8s-hardening lens a
// Wiz/Orca-class product carries. Per §13 this WRAPS OSS, not an in-house auditor.
//
// The parser is pure + tested; the live audit is gated on the kube-bench binary + config AND a reachable
// cluster (the honest gate — a running cluster is the SUT). Registry-tier (on-demand). Registered via init().
package kubebench

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

// KubeBench is the tool.Tool implementation.
type KubeBench struct{}

// New constructs a KubeBench wrapper.
func New() *KubeBench { return &KubeBench{} }

func (*KubeBench) Name() string              { return "kube-bench" }
func (*KubeBench) SandboxExecution() bool    { return true }
func (*KubeBench) MITRETechniques() []string { return []string{"T1610", "T1613"} } // deploy container / container+cluster discovery
func (*KubeBench) KnownArgs() []string       { return []string{"target", "targets", "benchmark"} }

// Run audits the cluster against the CIS Kubernetes Benchmark and normalizes the JSON into findings.
//
// Recognized args:
//
//	"targets"   string — optional, kube-bench node roles (e.g. "master,node,etcd,policies")
//	"benchmark" string — optional, a specific CIS benchmark version (e.g. "cis-1.23")
//
// kube-bench prints its JSON to stdout with --json; a non-zero exit (checks failed) is NOT a wrapper error.
func (*KubeBench) Run(ctx context.Context, args tool.Args) (tool.Result, error) {
	argv := []string{"run", "--json"}
	if t, _ := args["targets"].(string); strings.TrimSpace(t) != "" {
		argv = append(argv, "--targets", t)
	}
	if b, _ := args["benchmark"].(string); strings.TrimSpace(b) != "" {
		argv = append(argv, "--benchmark", b)
	}
	cmd := exec.CommandContext(ctx, "kube-bench", argv...)
	stdout, err := cmd.Output()
	if err != nil {
		var ee *exec.ExitError
		if !errors.As(err, &ee) {
			return tool.Result{}, fmt.Errorf("kube-bench: exec: %w", err)
		}
		// non-zero exit with JSON on stdout = failed checks; fall through to parse.
	}
	return tool.Result{Output: string(stdout), Findings: parse(stdout)}, nil
}

// kubeBenchReport is the slice of kube-bench's JSON we rely on.
type kubeBenchReport struct {
	Controls []kbControl `json:"Controls"`
}

type kbControl struct {
	ID    string   `json:"id"`
	Text  string   `json:"text"`
	Tests []kbTest `json:"tests"`
}

type kbTest struct {
	Section string     `json:"section"`
	Results []kbResult `json:"results"`
}

type kbResult struct {
	TestNumber  string `json:"test_number"`
	TestDesc    string `json:"test_desc"`
	Status      string `json:"status"` // PASS | FAIL | WARN | INFO
	Scored      bool   `json:"scored"`
	Remediation string `json:"remediation"`
}

// parse normalizes kube-bench's report into findings — one per FAIL/WARN check (PASS/INFO are not
// findings). Pure — the testable core. Sorted by test number for determinism.
func parse(blob []byte) []types.SandboxEmittedFinding {
	blob = bytes.TrimSpace(blob)
	if len(blob) == 0 || blob[0] != '{' {
		return nil
	}
	var rep kubeBenchReport
	if json.Unmarshal(blob, &rep) != nil {
		return nil
	}
	var out []types.SandboxEmittedFinding
	for _, c := range rep.Controls {
		for _, tst := range c.Tests {
			for _, r := range tst.Results {
				status := strings.ToUpper(strings.TrimSpace(r.Status))
				if status != "FAIL" && status != "WARN" {
					continue // PASS / INFO are not findings
				}
				raw, _ := json.Marshal(r)
				desc := r.TestDesc
				if r.Remediation != "" {
					desc += "\nRemediation: " + r.Remediation
				}
				out = append(out, types.SandboxEmittedFinding{
					RuleID:      "kube-bench::" + strings.TrimSpace(r.TestNumber),
					Tool:        "kube-bench",
					Severity:    severityOf(status, r.Scored),
					Endpoint:    "CIS " + strings.TrimSpace(r.TestNumber),
					Title:       fmt.Sprintf("CIS %s: %s", strings.TrimSpace(r.TestNumber), firstLine(r.TestDesc)),
					Description: desc,
					RawOutput:   raw,
					ToolArgs:    map[string]string{"status": status, "control": c.ID, "section": tst.Section},
				})
			}
		}
	}
	if len(out) == 0 {
		return nil
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].RuleID < out[j].RuleID })
	return out
}

// severityOf: a FAILED scored control is high (a hard CIS requirement); a FAILED unscored control is
// medium; a WARN (manual-check / not-automatable) is low.
func severityOf(status string, scored bool) types.Severity {
	switch status {
	case "FAIL":
		if scored {
			return types.SeverityHigh
		}
		return types.SeverityMedium
	case "WARN":
		return types.SeverityLow
	default:
		return types.SeverityInfo
	}
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}
