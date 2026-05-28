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
func (*Prowler) Run(ctx context.Context, args tool.Args) (tool.Result, error) {
	provider, _ := args["target"].(string)
	provider = strings.ToLower(strings.TrimSpace(provider))
	switch provider {
	case "aws", "gcp", "azure", "kubernetes":
	case "":
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

func init() { tool.Register(New()) }
