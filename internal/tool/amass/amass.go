// Package amass wraps the OWASP amass subdomain enumerator as a tsengine
// recon Tool for the domain asset. amass is a second enumeration ENGINE
// alongside subfinder + crt.sh — more passive sources = higher subdomain
// recall (the union is what matters). Registers via init().
//
// Passive by default (no active brute force / resolution) to stay
// non-intrusive; STRIX-style active mode is intentionally not exposed
// here. Requires the amass binary (Dockerfile install).
package amass

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"

	"github.com/ClatTribe/tsengine/internal/tool"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// Amass is the tool.Tool implementation.
type Amass struct{}

// New constructs an Amass wrapper.
func New() *Amass { return &Amass{} }

func (*Amass) Name() string              { return "amass" }
func (*Amass) SandboxExecution() bool    { return true }
func (*Amass) MITRETechniques() []string { return []string{"T1590.005"} }

// KnownArgs declares the recognized arg keys (tool.ArgSpec).
func (*Amass) KnownArgs() []string { return []string{"target", "timeout"} }

// Run invokes `amass enum -passive`. Recognized args:
//
//	"target"  string — required, the apex domain.
//	"timeout" int    — optional, enum timeout in MINUTES (amass unit).
func (*Amass) Run(ctx context.Context, args tool.Args) (tool.Result, error) {
	target, _ := args["target"].(string)
	target = strings.ToLower(strings.TrimSpace(target))
	if target == "" {
		return tool.Result{}, errors.New("amass: missing required arg 'target'")
	}
	cli := []string{"enum", "-passive", "-d", target, "-nocolor", "-silent"}
	if t, ok := args["timeout"].(int); ok && t > 0 {
		cli = append(cli, "-timeout", fmt.Sprintf("%d", t))
	}
	cmd := exec.CommandContext(ctx, "amass", cli...)
	stdout, err := cmd.Output()
	if err != nil {
		var ee *exec.ExitError
		if !errors.As(err, &ee) {
			return tool.Result{}, fmt.Errorf("amass: exec: %w", err)
		}
	}
	findings, surface := parse(stdout, target)
	return tool.Result{Output: string(stdout), Findings: findings, DiscoveredURLs: surface}, nil
}

// parse reads amass's plain-text subdomain lines (one host per line, ANSI
// already suppressed via -nocolor). Scoped to the apex, deduped, ordered.
func parse(blob []byte, apex string) ([]types.SandboxEmittedFinding, []string) {
	if len(blob) == 0 {
		return nil, nil
	}
	seen := map[string]struct{}{}
	var findings []types.SandboxEmittedFinding
	var surface []string
	sc := bufio.NewScanner(bytes.NewReader(blob))
	sc.Buffer(make([]byte, 0, 8*1024), 256*1024)
	for sc.Scan() {
		host := strings.ToLower(strings.TrimSpace(sc.Text()))
		// amass -silent prints bare hostnames; ignore any decorated lines.
		if host == "" || strings.ContainsAny(host, " \t") {
			continue
		}
		if host != apex && !strings.HasSuffix(host, "."+apex) {
			continue
		}
		if _, dup := seen[host]; dup {
			continue
		}
		seen[host] = struct{}{}
		findings = append(findings, types.SandboxEmittedFinding{
			RuleID:          "amass::subdomain-found",
			Tool:            "amass",
			Severity:        types.SeverityInfo,
			Endpoint:        host,
			Title:           "Subdomain discovered: " + host,
			Description:     "via OWASP amass (passive)",
			MITRETechniques: []string{"T1590.005"},
			ToolArgs:        map[string]string{"source": "amass"},
		})
		surface = append(surface, host)
	}
	return findings, surface
}

func init() { tool.Register(New()) }
