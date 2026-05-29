// Package cloudfox wraps BishopFox's CloudFox (read-only cloud IAM /
// attack-path enumeration) as a REGISTRY-TIER tsengine Tool for the
// cloud_account asset. Posture checks (prowler/scoutsuite) answer "is this
// misconfigured?"; CloudFox answers "what can an attacker reach from
// here?" — the IAM privilege-escalation depth strix's gap-analysis called
// "the credibility bar" and never shipped. Registry-tier: it never fires
// in the L1 prepass; it's reached on-demand via the tool-replay API /
// dispatch_l2_probe, gated by explicit scope opt-in. Registers via init().
package cloudfox

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"

	"github.com/ClatTribe/tsengine/internal/tool"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// CloudFox is the tool.Tool implementation.
type CloudFox struct{}

// New constructs a CloudFox wrapper.
func New() *CloudFox { return &CloudFox{} }

func (*CloudFox) Name() string              { return "cloudfox" }
func (*CloudFox) SandboxExecution() bool    { return true }
func (*CloudFox) MITRETechniques() []string { return []string{"T1078.004", "T1098", "T1069.003"} }

// KnownArgs declares the recognized arg keys (tool.ArgSpec).
func (*CloudFox) KnownArgs() []string { return []string{"target", "command"} }

// Run executes a read-only CloudFox check. Recognized args:
//
//	"target"  string — required, provider: "aws" | "azure" | "gcp".
//	"command" string — optional CloudFox subcommand (default "permissions").
//
// CloudFox is an INVESTIGATION tool: its value is the raw attack-path
// inventory the security engineer reads, so the wrapper preserves stdout
// in Result.Output and emits a single info finding marking the run. (No
// finding-per-edge parsing — that's the engineer's analysis, not L1's.)
func (*CloudFox) Run(ctx context.Context, args tool.Args) (tool.Result, error) {
	provider, _ := args["target"].(string)
	provider = strings.ToLower(strings.TrimSpace(provider))
	switch provider {
	case "aws", "azure", "gcp":
	case "":
		return tool.Result{}, errors.New("cloudfox: missing required arg 'target' (aws|azure|gcp)")
	default:
		return tool.Result{}, fmt.Errorf("cloudfox: unsupported provider %q", provider)
	}
	command := "permissions"
	if c, ok := args["command"].(string); ok && strings.TrimSpace(c) != "" {
		command = c
	}

	cmd := exec.CommandContext(ctx, "cloudfox", provider, command)
	out, err := cmd.CombinedOutput()
	if err != nil {
		var ee *exec.ExitError
		if !errors.As(err, &ee) {
			// Binary missing or auth failure — surface, don't crash.
			return tool.Result{Output: "cloudfox: " + err.Error()}, nil
		}
	}
	findings := []types.SandboxEmittedFinding{{
		RuleID:          "cloudfox::" + command,
		Tool:            "cloudfox",
		Severity:        types.SeverityInfo,
		Endpoint:        provider,
		Title:           "CloudFox IAM enumeration: " + command,
		Description:     "Read-only attack-path inventory; review raw output for privilege-escalation edges.",
		MITRETechniques: []string{"T1098", "T1069.003"},
		ToolArgs:        map[string]string{"command": command},
	}}
	return tool.Result{Output: string(out), Findings: findings}, nil
}

func init() { tool.Register(New()) }
