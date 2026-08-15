// Package garak wraps NVIDIA's garak (https://github.com/NVIDIA/garak) — the leading OSS LLM
// vulnerability scanner — as a tsengine Tool.
//
// It closes the one row on the CTO checklist we had to mark UNBUILT: "red-team agent workflows for
// jailbreaks and data exfiltration before launch". Testing a customer's OWN LLM features is genuine
// whitespace — we cover AI governance (ISO 42001, NIST AI RMF) and AI inventory today, but nothing
// was probing whether their assistant can be talked out of its instructions.
//
// Wrapped, not written (§13). garak carries hundreds of maintained probes across prompt injection,
// jailbreak, training-data leakage, encoding attacks and malware generation; an in-house version of
// that would be perpetually a year behind, and the whole point of a checklist row naming its scanner
// is that the customer can run the same one and get the same answer.
//
// # This tool is ACTIVE by nature, and that governs how it may be used
//
// Every other scanner here observes. garak ATTACKS: it sends adversarial prompts to a live endpoint
// and reads what comes back. So it belongs behind the same gate as the pentester — an authorized
// engagement with recorded consent and a named human (§18.4, pentest.RoE.ActiveAuthorized). It is
// registered as a registry-tier tool rather than an anchor precisely so it never fires on a routine
// scan: reaching it takes a deliberate act.
//
// # Grounding (§10)
//
// A garak hit carries the prompt that was sent and the response that came back. That is evidence a
// human can read and judge, which matters more here than anywhere else in the product — "the model
// said something bad" is a claim whose severity depends on context no scanner has. The finding
// reports what was asked and what was answered; it does not assert business impact.
package garak

import (
	"bufio"
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

// Garak is the tool.Tool implementation.
type Garak struct{}

// New constructs a Garak wrapper.
func New() *Garak { return &Garak{} }

func (*Garak) Name() string           { return "garak" }
func (*Garak) SandboxExecution() bool { return true }

// MITRETechniques: garak probes the model-facing equivalents of command injection and defence
// evasion — an injected instruction that changes what the application does on the attacker's behalf.
func (*Garak) MITRETechniques() []string { return []string{"T1059", "T1027", "T1552"} }

// KnownArgs declares the recognized arg keys (tool.ArgSpec). A mis-wired key is a loud CI failure
// rather than a silent recall drop (§5.2 C4).
func (*Garak) KnownArgs() []string {
	return []string{"model_type", "model_name", "probes", "generations", "endpoint"}
}

// Run probes an LLM endpoint for prompt-injection, jailbreak and leakage weaknesses.
//
//	"model_type"  string — garak generator family (openai | huggingface | rest | ollama). Required.
//	"model_name"  string — the model or, for "rest", the config naming the customer's endpoint.
//	"probes"      string — comma-separated probe set. Empty → garak's own default selection.
//	"generations" int    — attempts per probe. Empty → garak's default.
func (*Garak) Run(ctx context.Context, args tool.Args) (tool.Result, error) {
	modelType, _ := args["model_type"].(string)
	if strings.TrimSpace(modelType) == "" {
		return tool.Result{}, errors.New("garak: missing required arg 'model_type'")
	}
	modelName, _ := args["model_name"].(string)

	argv := []string{"--model_type", modelType, "--report_prefix", "tsengine", "--narrow_output"}
	if strings.TrimSpace(modelName) != "" {
		argv = append(argv, "--model_name", modelName)
	}
	if p, _ := args["probes"].(string); strings.TrimSpace(p) != "" {
		argv = append(argv, "--probes", p)
	}
	if g := intArg(args["generations"]); g > 0 {
		argv = append(argv, "--generations", fmt.Sprint(g))
	}

	cmd := exec.CommandContext(ctx, "garak", argv...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	if err != nil {
		var ee *exec.ExitError
		if !errors.As(err, &ee) {
			// A missing binary or a spawn failure is a REAL failure and must not be reported as a
			// clean run. An LLM app that was never probed is not an LLM app that passed.
			return tool.Result{}, fmt.Errorf("garak: exec: %w (%s)", err, truncate(stderr.String(), 300))
		}
		// garak exits non-zero when probes hit — that is a result, not an error.
	}
	out := stdout.String()
	return tool.Result{Output: out, Findings: Parse(out)}, nil
}

// hit is one garak attempt report line. garak emits JSONL; the entries with entry_type "attempt"
// and a non-zero detector score are the ones that found something.
type hit struct {
	EntryType string             `json:"entry_type"`
	Probe     string             `json:"probe_classname"`
	Detector  string             `json:"detector_results"`
	Status    int                `json:"status"`
	Prompt    string             `json:"prompt"`
	Outputs   []string           `json:"outputs"`
	Results   map[string]float64 `json:"detector_scores"`
}

// Parse turns garak's JSONL report into findings. Exported for the wrapper's tests.
//
// ONLY A SCORED DETECTION BECOMES A FINDING. garak logs every attempt, including the ones the model
// correctly refused; treating those as findings would report a working guardrail as a vulnerability,
// which is the fastest way to teach someone to ignore this scanner.
func Parse(out string) []types.SandboxEmittedFinding {
	var fs []types.SandboxEmittedFinding
	sc := bufio.NewScanner(strings.NewReader(out))
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	seen := map[string]bool{}
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if !strings.HasPrefix(line, "{") {
			continue
		}
		var h hit
		if json.Unmarshal([]byte(line), &h) != nil {
			continue
		}
		if h.EntryType != "attempt" || !scored(h) {
			continue
		}
		probe := nz(h.Probe, "unknown")
		if seen[probe] {
			continue // one finding per probe class; the evidence names the first hit
		}
		seen[probe] = true
		fs = append(fs, types.SandboxEmittedFinding{
			RuleID:          "garak::" + probe,
			Tool:            "garak",
			Severity:        severityFor(probe),
			CWE:             cweFor(probe),
			MITRETechniques: []string{"T1059", "T1027"},
			Title:           "LLM guardrail bypassed: " + probe,
			// The evidence IS the prompt and the response. A human reading this can judge whether it
			// matters for their application, which no scanner can decide for them.
			Description: "The model was sent an adversarial prompt and produced a response the " +
				probe + " detector flagged.\n\nPrompt: " + truncate(h.Prompt, 600) +
				"\n\nResponse: " + truncate(firstOutput(h.Outputs), 600),
		})
	}
	return fs
}

func scored(h hit) bool {
	for _, v := range h.Results {
		if v > 0 {
			return true
		}
	}
	return false
}

// severityFor grades by what the probe class actually achieves. Deliberately conservative: a model
// saying something rude is not the same as one leaking its system prompt or another user's data, and
// flattening them into one severity makes the high ones unfindable.
func severityFor(probe string) types.Severity {
	p := strings.ToLower(probe)
	switch {
	case strings.Contains(p, "leak"), strings.Contains(p, "exfil"), strings.Contains(p, "xss"),
		strings.Contains(p, "promptinject"), strings.Contains(p, "injection"):
		return types.SeverityHigh
	case strings.Contains(p, "jailbreak"), strings.Contains(p, "dan"), strings.Contains(p, "encoding"),
		strings.Contains(p, "malwaregen"):
		return types.SeverityMedium
	default:
		return types.SeverityLow
	}
}

// cweFor maps a probe class to the weakness it demonstrates, so an AI finding flows into the same
// compliance crosswalk as everything else rather than sitting in its own silo.
func cweFor(probe string) []string {
	p := strings.ToLower(probe)
	switch {
	case strings.Contains(p, "promptinject"), strings.Contains(p, "injection"):
		return []string{"CWE-77"} // improper neutralization of special elements in a command
	case strings.Contains(p, "leak"), strings.Contains(p, "exfil"):
		return []string{"CWE-200"} // exposure of sensitive information
	case strings.Contains(p, "xss"):
		return []string{"CWE-79"}
	}
	return nil
}

func firstOutput(out []string) string {
	for _, o := range out {
		if strings.TrimSpace(o) != "" {
			return o
		}
	}
	return "(no output recorded)"
}

func truncate(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func nz(s, def string) string {
	if strings.TrimSpace(s) == "" {
		return def
	}
	return s
}

func intArg(v any) int {
	switch n := v.(type) {
	case int:
		return n
	case float64:
		return int(n)
	}
	return 0
}

func init() { tool.Register(New()) }
