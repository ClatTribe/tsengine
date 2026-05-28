// Package nmap wraps the nmap port + service scanner as a tsengine
// Tool. Registers via init().
//
// Phase 3 runs nmap with -sV (service/version detection) on the default
// port set. The ip Handler's filter constrains the port range; per-port
// nuclei tag-routing arrives later in Phase 3.x per arch.md.
package nmap

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"

	"github.com/ClatTribe/tsengine/internal/tool"
)

// Nmap is the tool.Tool implementation.
type Nmap struct{}

// New constructs an Nmap wrapper.
func New() *Nmap { return &Nmap{} }

func (*Nmap) Name() string             { return "nmap" }
func (*Nmap) SandboxExecution() bool   { return true }
func (*Nmap) MITRETechniques() []string { return []string{"T1046"} }

// Run invokes nmap with XML output.
//
// Recognized args:
//
//	"target" string — required, IP / hostname / CIDR
//	"ports"  string — optional -p value (default: top-1000)
//	"timing" string — optional -T value (e.g. "T3"); default "T4"
//
// Output: one finding per open port.
func (*Nmap) Run(ctx context.Context, args tool.Args) (tool.Result, error) {
	target, _ := args["target"].(string)
	if strings.TrimSpace(target) == "" {
		return tool.Result{}, errors.New("nmap: missing required arg 'target'")
	}

	timing := "-T4"
	if t, ok := args["timing"].(string); ok && t != "" {
		timing = fmt.Sprintf("-%s", t)
	}

	cliArgs := []string{"-oX", "-", "-sV", timing, "-Pn"}
	if p, ok := args["ports"].(string); ok && p != "" {
		cliArgs = append(cliArgs, "-p", p)
	}
	cliArgs = append(cliArgs, target)

	cmd := exec.CommandContext(ctx, "nmap", cliArgs...)
	stdout, err := cmd.Output()
	if err != nil {
		var ee *exec.ExitError
		if !errors.As(err, &ee) {
			return tool.Result{}, fmt.Errorf("nmap: exec: %w", err)
		}
	}

	findings := parseXML(stdout)
	return tool.Result{
		Output:   string(stdout),
		Findings: findings,
	}, nil
}

func init() {
	tool.Register(New())
}
