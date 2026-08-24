// Package prowler wraps the prowler multi-cloud posture scanner as a
// tsengine Tool. It's the cloud_account asset's anchor. Registers via
// init().
//
// prowler needs cloud credentials (forwarded into the sandbox via env —
// see the cloud asset Handler + CLI). EXIT CONTRACT (ADR 0031 D1): no
// --exit-code-style flag is passed, so EVERY non-zero exit is an ERROR —
// bad/expired credentials chief among them — and is returned via
// tool.Failed so the pass degrades LOUDLY. A missing output file after a
// clean exit is equally an error: a cloud scan with no output has not
// looked, and "not looked" must never render as clean.
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
	// Output() (not Run/CombinedOutput) so ExitError.Stderr is populated and
	// tool.ExitDetail can carry the FATAL line naming the cause.
	_, runErr := cmd.Output()
	if tool.Failed(runErr) {
		return tool.Result{}, fmt.Errorf("prowler: %s", tool.ExitDetail(runErr))
	}

	blob, readErr := readOCSF(outDir)
	if readErr != nil {
		return tool.Result{}, fmt.Errorf(
			"prowler: exited cleanly but produced no OCSF output (%v) — this is an authentication or "+
				"execution failure, NEVER a clean estate; fix the credentials and re-run", readErr)
	}
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
