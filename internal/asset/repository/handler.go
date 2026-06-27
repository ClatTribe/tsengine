// Package repository is the Handler for the repository asset type.
// See arch.md "repository" for the canonical anchor + registry + filter
// matrix.
//
// The source tree is bind-mounted read-only into the sandbox at
// /workspace by the CLI (cmd/tsengine wires sandbox.Mount). All
// repository tools therefore scan WorkspacePath, regardless of the
// host-side path the user passed — that path is preserved in
// asset.Target for the dashboard.
package repository

import (
	"context"

	"github.com/ClatTribe/tsengine/internal/asset"
	"github.com/ClatTribe/tsengine/internal/asset/common"
	"github.com/ClatTribe/tsengine/internal/tool"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// WorkspacePath is the in-sandbox mount point for the scanned repo. The
// CLI mounts the user's --target here read-only.
const WorkspacePath = "/workspace"

// Handler implements asset.Handler for repository targets.
type Handler struct {
	anchors  []tool.Tool
	registry []tool.Tool
}

// NewHandler resolves anchor + registry tools from the global registry.
func NewHandler() *Handler {
	return &Handler{
		anchors:  common.ResolveTools(anchorNames),
		registry: common.ResolveTools(registryNames),
	}
}

func (*Handler) Type() types.AssetType { return types.AssetRepository }

func (h *Handler) Anchors() []tool.Tool  { return h.anchors }
func (h *Handler) Registry() []tool.Tool { return h.registry }

// PlanAnchors targets the in-sandbox workspace mount for every tool.
// trivy needs mode=fs; grype takes a "dir:" source string. trivy + grype
// (different SCA DBs) and gitleaks + trufflehog (different secret
// engines) give the L1.5 corroborator cross-source agreement.
func (h *Handler) PlanAnchors(_ types.Asset) []asset.Dispatch {
	out := make([]asset.Dispatch, 0, len(h.anchors))
	for _, t := range h.anchors {
		args := tool.Args{"target": WorkspacePath}
		switch t.Name() {
		case "trivy":
			args["mode"] = "fs"
		case "grype", "syft":
			// grype + syft take a source string; "dir:" scans the tree.
			args["target"] = "dir:" + WorkspacePath
		case "hadolint":
			// hadolint lints a single Dockerfile; missing file → no
			// findings (the wrapper degrades gracefully).
			args["target"] = WorkspacePath + "/Dockerfile"
		}
		out = append(out, asset.Dispatch{Tool: t, Args: args})
	}
	return out
}

// Filter applies the file-tree skip (arch.md "repository"): tools that
// honor it should not descend into vendored / build output. Since the
// anchors already scan WorkspacePath wholesale, the orchestrator-level
// filter is a no-op today; the skip is enforced by passing exclude
// globs to the tools (Phase 3.x adds per-tool --exclude wiring). The
// hook stays here so the pipeline shape matches the other assets.
func (h *Handler) Filter(_ context.Context, _ types.Asset, in []asset.Dispatch) []asset.Dispatch {
	return in
}

func (h *Handler) Normalize(results []tool.Result) []types.Finding {
	out := common.Normalize(results)
	// Supply-chain malware: match the syft SBOM's dependency set against the
	// known-malicious corpus (distinct from the SCA tools' CVE findings).
	return append(out, common.SupplyChainFindings(results)...)
}

// SkipDirs is the file-tree exclusion set (arch.md "repository" filter).
// Exposed for the tool wrappers / Phase 3.x --exclude wiring.
var SkipDirs = []string{
	"node_modules", "vendor", ".git", "__pycache__", "dist", "build", ".venv",
}

// anchorNames: SAST (semgrep), secrets (gitleaks + trufflehog — different
// engines, corroborate), SCA (trivy fs + grype + osv-scanner — three
// different DBs, strong corroboration), IaC (checkov — the HashiCorp/
// cloud-native coverage strix's in-house engine lacked), Dockerfile lint
// (hadolint), SBOM (syft → compliance evidence). CodeQL stays registry-
// tier (the taint-flow depth jump).
var anchorNames = []string{
	"semgrep",
	"gitleaks",
	"trufflehog",
	"trivy",
	"grype",
	"osv-scanner",
	"checkov",
	"hadolint",
	"syft",
}

var registryNames = []string{
	// govulncheck — Go call-graph reachability (SCA false-positive killer).
	// Escalation-fired when the tree looks like a Go project; reports only
	// reachable vulnerabilities, corroborating the SCA tools' raw CVE list.
	"govulncheck",
	// gosec — Go-specific security SAST (weak crypto, hardcoded creds, SQL string-building,
	// unhandled security errors) — complements semgrep's generic packs with Go-idiomatic rules.
	"gosec",
	// Phase 3.x: CodeQL, brakeman, staticcheck, snyk-code, kics, terrascan
}
