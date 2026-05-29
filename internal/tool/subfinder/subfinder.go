// Package subfinder wraps the projectdiscovery/subfinder asset-discovery
// tool. One Tool implementation; registers via init().
//
// subfinder is recon, not detection — its "findings" are discovered
// subdomains. The domain Handler treats them as recon artifacts (info
// severity) so they pass through the L1 dashboard for the
// security-engineer audience to act on.
package subfinder

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"

	"github.com/ClatTribe/tsengine/internal/tool"
)

// Subfinder is the tool.Tool implementation.
type Subfinder struct{}

// New constructs a Subfinder wrapper.
func New() *Subfinder { return &Subfinder{} }

func (*Subfinder) Name() string             { return "subfinder" }
func (*Subfinder) SandboxExecution() bool   { return true }
func (*Subfinder) MITRETechniques() []string { return []string{"T1590.005"} }

// Run invokes subfinder.
//
// Recognized args:
//
//	"target" string — required, the apex domain (e.g. "example.com")
//	"timeout" int — optional, per-source timeout seconds
//
// Output: one finding per discovered subdomain.
func (*Subfinder) Run(ctx context.Context, args tool.Args) (tool.Result, error) {
	target, _ := args["target"].(string)
	if strings.TrimSpace(target) == "" {
		return tool.Result{}, errors.New("subfinder: missing required arg 'target'")
	}

	cliArgs := []string{"-d", target, "-oJ", "-silent", "-duc"}
	if t, ok := args["timeout"].(int); ok && t > 0 {
		cliArgs = append(cliArgs, "-timeout", fmt.Sprintf("%d", t))
	}

	cmd := exec.CommandContext(ctx, "subfinder", cliArgs...)
	stdout, err := cmd.Output()
	if err != nil {
		var ee *exec.ExitError
		if !errors.As(err, &ee) {
			return tool.Result{}, fmt.Errorf("subfinder: exec: %w", err)
		}
	}

	findings := parseJSONL(stdout)
	// Mirror discovered subdomains into the recon channel so the domain
	// Handler (ReconHandler) can fan detection across them + emit child
	// assets. Findings keep their copy for the dashboard.
	surface := make([]string, 0, len(findings))
	for _, f := range findings {
		surface = append(surface, f.Endpoint)
	}
	return tool.Result{
		Output:         string(stdout),
		Findings:       findings,
		DiscoveredURLs: surface,
	}, nil
}

// KnownArgs declares the recognized arg keys (tool.ArgSpec).
func (*Subfinder) KnownArgs() []string { return []string{"target", "timeout"} }

func init() {
	tool.Register(New())
}
