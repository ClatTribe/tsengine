// Package nikto wraps Nikto, the classic web-server scanner, as a tsengine depth Tool for the web asset's
// registry tier. It complements nuclei's template engine with Nikto's distinct corpus: ~7k checks for
// dangerous/legacy CGIs, default + backup files, outdated server software, and missing/insecure HTTP headers —
// the breadth a security engineer reaches for to "dig deeper" on a web target. On-demand (registry-tier);
// registered via init().
package nikto

import (
	"context"
	"encoding/json"
	"errors"
	"os/exec"
	"strings"

	"github.com/ClatTribe/tsengine/internal/tool"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// Nikto is the tool.Tool implementation.
type Nikto struct{}

// New constructs a Nikto wrapper.
func New() *Nikto { return &Nikto{} }

func (*Nikto) Name() string              { return "nikto" }
func (*Nikto) SandboxExecution() bool    { return true }
func (*Nikto) MITRETechniques() []string { return []string{"T1595", "T1190"} } // active scanning; exploit public-facing app

// KnownArgs declares the recognized arg keys (tool.ArgSpec).
func (*Nikto) KnownArgs() []string { return []string{"target", "url"} }

// Run scans a web target. Recognized args:
//
//	"target"/"url" string — required, the http(s) host to scan.
func (*Nikto) Run(ctx context.Context, args tool.Args) (tool.Result, error) {
	target, _ := args["target"].(string)
	if strings.TrimSpace(target) == "" {
		target, _ = args["url"].(string)
	}
	if strings.TrimSpace(target) == "" {
		return tool.Result{}, errors.New("nikto: missing required arg 'target'")
	}
	// JSON to stdout, non-interactive, no automatic update. Nikto exits non-zero in some "found issues"
	// paths, so a non-ExitError is the only hard failure.
	cmd := exec.CommandContext(ctx, "nikto", "-h", target, "-Format", "json", "-output", "/dev/stdout", "-nointeractive", "-ask", "no")
	out, err := cmd.CombinedOutput()
	if err != nil {
		var ee *exec.ExitError
		if !errors.As(err, &ee) {
			return tool.Result{Output: "nikto: " + err.Error()}, nil
		}
	}
	return tool.Result{Output: string(out), Findings: parse(out)}, nil
}

// vuln is one Nikto finding; host wraps the run. Nikto's JSON top level is either a single host object or an
// array of them (version-dependent), so parse handles both.
type vuln struct {
	ID     string `json:"id"`
	Method string `json:"method"`
	URL    string `json:"url"`
	Msg    string `json:"msg"`
}
type host struct {
	Host            string `json:"host"`
	Port            string `json:"port"`
	Vulnerabilities []vuln `json:"vulnerabilities"`
}

func parse(blob []byte) []types.SandboxEmittedFinding {
	hosts := parseHosts(blob)
	var out []types.SandboxEmittedFinding
	for _, h := range hosts {
		for _, v := range h.Vulnerabilities {
			msg := strings.TrimSpace(v.Msg)
			if msg == "" {
				continue
			}
			endpoint := strings.TrimSpace(v.URL)
			if endpoint == "" {
				endpoint = h.Host
			}
			f := types.SandboxEmittedFinding{
				RuleID:          "nikto::" + nz(v.ID, "item"),
				Tool:            "nikto",
				Severity:        severityFor(msg),
				Endpoint:        endpoint,
				Title:           truncate(msg, 200),
				Description:     msg,
				MITRETechniques: []string{"T1595"},
			}
			if c := cweFor(msg); c != "" {
				f.CWE = []string{c}
			}
			out = append(out, f)
		}
	}
	return out
}

// parseHosts decodes either {host...} or [{host...}, ...].
func parseHosts(blob []byte) []host {
	var one host
	if json.Unmarshal(blob, &one) == nil && (one.Host != "" || len(one.Vulnerabilities) > 0) {
		return []host{one}
	}
	var many []host
	if json.Unmarshal(blob, &many) == nil {
		return many
	}
	return nil
}

// severityFor: Nikto carries no severity, so default to low (it's a breadth/hygiene scanner) and bump only on
// message patterns that clearly indicate exploitable danger — never a guessed high on a header note.
func severityFor(msg string) types.Severity {
	m := strings.ToLower(msg)
	for _, kw := range []string{"remote", "rce", "command exec", "sql inject", "shell", "backdoor", "traversal", "default account", "default password", "/admin", "phpmyadmin", "arbitrary file"} {
		if strings.Contains(m, kw) {
			return types.SeverityMedium
		}
	}
	return types.SeverityLow
}

// cweFor maps the common Nikto header/disclosure findings to a CWE; unmapped → none (never guessed).
func cweFor(msg string) string {
	m := strings.ToLower(msg)
	switch {
	case strings.Contains(m, "x-frame-options"), strings.Contains(m, "clickjack"):
		return "CWE-1021"
	case strings.Contains(m, "content-security-policy"), strings.Contains(m, "x-content-type-options"):
		return "CWE-693"
	case strings.Contains(m, "retrieved") && strings.Contains(m, "header"), strings.Contains(m, "server banner"), strings.Contains(m, "version"):
		return "CWE-200"
	case strings.Contains(m, "default file"), strings.Contains(m, "backup"), strings.Contains(m, "/admin"):
		return "CWE-552"
	}
	return ""
}

func nz(s, dflt string) string {
	if strings.TrimSpace(s) == "" {
		return dflt
	}
	return s
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func init() { tool.Register(New()) }
