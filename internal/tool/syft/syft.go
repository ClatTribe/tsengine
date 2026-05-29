// Package syft wraps anchore/syft (SBOM generator) as a tsengine Tool for
// the container_image + repository assets. syft is not a vulnerability
// detector — it produces the canonical CycloneDX SBOM that the compliance
// evidence bundle and the dependency inventory consume. It emits a single
// info finding (component count) and carries the full SBOM JSON in Output.
// Registers via init().
package syft

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strings"

	"github.com/ClatTribe/tsengine/internal/tool"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// Syft is the tool.Tool implementation.
type Syft struct{}

// New constructs a Syft wrapper.
func New() *Syft { return &Syft{} }

func (*Syft) Name() string              { return "syft" }
func (*Syft) SandboxExecution() bool    { return true }
func (*Syft) MITRETechniques() []string { return []string{"T1195.002"} }

// KnownArgs declares the recognized arg keys (tool.ArgSpec).
func (*Syft) KnownArgs() []string { return []string{"target"} }

// Run generates an SBOM. Recognized args:
//
//	"target" string — required, a syft source ("dir:/workspace", an image
//	                  ref, etc.).
func (*Syft) Run(ctx context.Context, args tool.Args) (tool.Result, error) {
	target, _ := args["target"].(string)
	if strings.TrimSpace(target) == "" {
		return tool.Result{}, errors.New("syft: missing required arg 'target'")
	}
	cmd := exec.CommandContext(ctx, "syft", target, "-o", "cyclonedx-json", "-q")
	stdout, err := cmd.Output()
	if err != nil {
		var ee *exec.ExitError
		if !errors.As(err, &ee) {
			return tool.Result{}, fmt.Errorf("syft: exec: %w", err)
		}
	}
	return tool.Result{Output: string(stdout), Findings: summarize(stdout, target)}, nil
}

// cyclonedx is the minimal CycloneDX shape we read to count components.
type cyclonedx struct {
	Components []struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	} `json:"components"`
}

// summarize emits one info finding recording the SBOM component count. The
// SBOM itself rides in Result.Output for the compliance bundle.
func summarize(blob []byte, target string) []types.SandboxEmittedFinding {
	var doc cyclonedx
	if json.Unmarshal(blob, &doc) != nil || len(doc.Components) == 0 {
		return nil
	}
	return []types.SandboxEmittedFinding{{
		RuleID:          "syft::sbom-generated",
		Tool:            "syft",
		Severity:        types.SeverityInfo,
		Endpoint:        target,
		Title:           fmt.Sprintf("SBOM generated: %d components", len(doc.Components)),
		Description:     "CycloneDX SBOM available in raw output for the compliance evidence bundle",
		MITRETechniques: []string{"T1195.002"},
		ToolArgs:        map[string]string{"component_count": fmt.Sprintf("%d", len(doc.Components))},
	}}
}

func init() { tool.Register(New()) }
