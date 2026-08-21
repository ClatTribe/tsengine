// Package prowler wraps the prowler multi-cloud posture scanner as a
// tsengine Tool. It's the cloud_account asset's anchor. Registers via
// init().
//
// prowler needs cloud credentials (forwarded into the sandbox via env —
// see the cloud asset Handler + CLI). Without credentials it exits
// reporting an auth error; the wrapper surfaces that as zero findings
// rather than a hard failure, so a misconfigured scan degrades
// gracefully.
package prowler

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/ClatTribe/tsengine/internal/tool"
)

// Prowler is the tool.Tool implementation.
type Prowler struct{}

// New constructs a Prowler wrapper.
func New() *Prowler { return &Prowler{} }

func (*Prowler) Name() string              { return "prowler" }
func (*Prowler) SandboxExecution() bool    { return true }
func (*Prowler) MITRETechniques() []string { return []string{"T1078.004", "T1530"} }

// Run executes prowler against a cloud provider.
//
// Recognized args:
//
//	"target" string — required, the provider: "aws" | "gcp" | "azure"
//
// prowler writes OCSF JSON to an output directory; we read it back and
// parse the findings. Credentials arrive via the sandbox's environment
// (forwarded by the cloud Handler).
// SupportedProviders is the set of provider strings prowler accepts as its scan target. Exported so
// the code that DISPATCHES prowler (the connectors that set a cloud asset's Target) can be checked
// against the real list rather than a hand-copied one — an account id where a provider belongs is
// exactly the mismatch that made every cloud scan fail with "unsupported provider".
var SupportedProviders = map[string]bool{"aws": true, "gcp": true, "azure": true, "kubernetes": true}

// Accepts reports whether target is a provider prowler can scan (case/space-insensitive).
func Accepts(target string) bool {
	return SupportedProviders[strings.ToLower(strings.TrimSpace(target))]
}

func (*Prowler) Run(ctx context.Context, args tool.Args) (tool.Result, error) {
	provider, _ := args["target"].(string)
	provider = strings.ToLower(strings.TrimSpace(provider))
	switch {
	case SupportedProviders[provider]:
	case provider == "":
		return tool.Result{}, errors.New("prowler: missing required arg 'target' (aws|gcp|azure)")
	default:
		return tool.Result{}, fmt.Errorf("prowler: unsupported provider %q", provider)
	}

	outDir, err := os.MkdirTemp("", "prowler-")
	if err != nil {
		return tool.Result{}, err
	}
	defer os.RemoveAll(outDir)

	cmd := exec.CommandContext(ctx, "prowler", provider,
		"--output-formats", "json-ocsf",
		"--output-directory", outDir,
		"--output-filename", "prowler",
		"--ignore-exit-code-3",
	)
	combined, runErr := cmd.CombinedOutput()

	blob, readErr := readOCSF(outDir)
	if readErr != nil {
		// No output file — prowler likely failed to authenticate. Degrade
		// gracefully: no findings, surface prowler's stderr for the
		// security engineer to see why.
		return tool.Result{Output: string(combined)}, nil
	}
	_ = runErr
	return tool.Result{Output: string(blob), Findings: parseOCSF(blob)}, nil
}

// readOCSF finds the prowler OCSF json output file in the output dir.
func readOCSF(dir string) ([]byte, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".ocsf.json") || strings.HasSuffix(e.Name(), ".json") {
			return os.ReadFile(filepath.Join(dir, e.Name())) //nolint:gosec // temp dir we created
		}
	}
	return nil, errors.New("prowler: no json output produced")
}

// KnownArgs declares the recognized arg keys (tool.ArgSpec).
func (*Prowler) KnownArgs() []string { return []string{"target"} }

func init() { tool.Register(New()) }
