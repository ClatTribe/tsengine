// Package trivy wraps the aquasecurity/trivy CVE + misconfig + secret
// scanner as a tsengine Tool.
//
// trivy is multi-modal — image scanning, filesystem scanning, repository
// scanning, k8s, AWS, etc. This wrapper exposes the two modes Phase 3
// uses: "image" (container_image asset) and "fs" (repository asset).
//
// Importing the package registers the wrapper via init().
package trivy

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"

	"github.com/ClatTribe/tsengine/internal/tool"
)

// Trivy is the tool.Tool implementation.
type Trivy struct{}

// New constructs a Trivy wrapper.
func New() *Trivy { return &Trivy{} }

func (*Trivy) Name() string           { return "trivy" }
func (*Trivy) SandboxExecution() bool { return true }
func (*Trivy) MITRETechniques() []string {
	return []string{"T1195.002", "T1610", "T1552.001"}
}

// Run invokes trivy.
//
// Recognized args:
//
//	"mode"   string — required, "image" or "fs"
//	"target" string — required, image ref (image mode) or path (fs mode)
//	"severity" string — optional, comma-separated CRITICAL,HIGH,... filter
//
// Findings end up in Result.Findings; Result.Output carries the raw
// JSON blob.
func (*Trivy) Run(ctx context.Context, args tool.Args) (tool.Result, error) {
	mode, _ := args["mode"].(string)
	if mode == "" {
		return tool.Result{}, errors.New("trivy: missing required arg 'mode' (image|fs)")
	}
	switch mode {
	case "image", "fs":
	default:
		return tool.Result{}, fmt.Errorf("trivy: unsupported mode %q", mode)
	}

	target, _ := args["target"].(string)
	if strings.TrimSpace(target) == "" {
		return tool.Result{}, errors.New("trivy: missing required arg 'target'")
	}

	cliArgs := []string{mode, "--format", "json", "--quiet"}
	if sev, ok := args["severity"].(string); ok && sev != "" {
		cliArgs = append(cliArgs, "--severity", sev)
	}
	// Base-layer skip (container base-image noise reduction, A5): only
	// surface vulns that have a fix, so a customer's app-fixable CVEs stand
	// apart from the unfixable alpine/debian baseline. strix's Q5.42
	// filtration dimension for container_image.
	if iu, ok := args["ignore_unfixed"].(bool); ok && iu {
		cliArgs = append(cliArgs, "--ignore-unfixed")
	}
	cliArgs = append(cliArgs, target)

	cmd := exec.CommandContext(ctx, "trivy", cliArgs...)
	stdout, err := cmd.Output()
	if err != nil {
		var ee *exec.ExitError
		if !errors.As(err, &ee) {
			return tool.Result{}, fmt.Errorf("trivy: exec: %w", err)
		}
		// trivy may exit non-zero on findings-found / network issues;
		// still attempt parse.
	}

	findings := parseReport(stdout)
	return tool.Result{
		Output:   string(stdout),
		Findings: findings,
	}, nil
}

// KnownArgs declares the recognized arg keys (tool.ArgSpec).
func (*Trivy) KnownArgs() []string {
	return []string{"target", "mode", "severity", "ignore_unfixed"}
}

func init() {
	tool.Register(New())
}
