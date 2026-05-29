// Package cosign wraps sigstore/cosign as a tsengine Tool for the
// container_image asset. It fills a gap trivy/grype/syft can't: they find
// CVEs and components; cosign answers SUPPLY-CHAIN TRUST — is this image
// SIGNED, and does it carry SLSA provenance/attestations? An unsigned
// production image is a supply-chain hygiene finding. Registers via init().
package cosign

import (
	"context"
	"errors"
	"os/exec"
	"strings"

	"github.com/ClatTribe/tsengine/internal/tool"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// Cosign is the tool.Tool implementation.
type Cosign struct{}

// New constructs a Cosign wrapper.
func New() *Cosign { return &Cosign{} }

func (*Cosign) Name() string              { return "cosign" }
func (*Cosign) SandboxExecution() bool    { return true }
func (*Cosign) MITRETechniques() []string { return []string{"T1195.002"} }

// KnownArgs declares the recognized arg keys (tool.ArgSpec).
func (*Cosign) KnownArgs() []string { return []string{"target"} }

// runner is swapped in tests; production shells out to `cosign tree`.
var runner = func(ctx context.Context, image string) ([]byte, bool) {
	cmd := exec.CommandContext(ctx, "cosign", "tree", image)
	out, err := cmd.CombinedOutput()
	// cosign tree exits non-zero when nothing is attached; that's the
	// "unsigned" signal, not a tool error.
	return out, err == nil
}

// Run inspects an image's signatures + attestations. Recognized args:
//
//	"target" string — required, the image ref.
//
// No signatures/attestations → a supply-chain hygiene finding.
func (*Cosign) Run(ctx context.Context, args tool.Args) (tool.Result, error) {
	image, _ := args["target"].(string)
	image = strings.TrimSpace(image)
	if image == "" {
		return tool.Result{}, errors.New("cosign: missing required arg 'target'")
	}
	out, ok := runner(ctx, image)
	return tool.Result{Output: string(out), Findings: assess(out, ok, image)}, nil
}

// hasArtifacts reports whether `cosign tree` output shows any attached
// signatures or attestations.
func hasArtifacts(out []byte) bool {
	s := strings.ToLower(string(out))
	return strings.Contains(s, "signatures") ||
		strings.Contains(s, "attestations") ||
		strings.Contains(s, "sboms")
}

func assess(out []byte, ok bool, image string) []types.SandboxEmittedFinding {
	if ok && hasArtifacts(out) {
		return nil // signed / attested — no finding
	}
	return []types.SandboxEmittedFinding{{
		RuleID:          "cosign::unsigned-image",
		Tool:            "cosign",
		Severity:        types.SeverityLow,
		Endpoint:        image,
		Title:           "Container image is unsigned / has no provenance",
		Description:     "No cosign signature or SLSA attestation found. The image's origin can't be cryptographically verified — supply-chain integrity gap.",
		MITRETechniques: []string{"T1195.002"},
	}}
}

func init() { tool.Register(New()) }
