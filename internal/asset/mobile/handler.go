// Package mobile is the Handler for the mobile_application asset type —
// an Android (APK / source) or iOS (IPA / source) app bundle. See arch.md
// "mobile_application" for the canonical anchor + registry + filter matrix.
//
// Like repository, mobile is single-stage: the app bundle IS the surface,
// so there is no recon → fan-out. The app's source tree / decompiled
// bundle is bind-mounted read-only into the sandbox at /workspace by the
// CLI (cmd/tsengine wires sandbox.Mount), and every tool scans that path,
// regardless of the host path the user passed.
//
// The mobile threat model is distinct from a generic repository's: the #1
// real-world findings are insecure local storage, weak crypto, exported
// components / unprotected deep links, hardcoded API keys & secrets, and
// vulnerable bundled native/3rd-party libs. The anchor set is curated for
// exactly that — mobsfscan (the leading OSS mobile SAST), gitleaks
// (hardcoded secrets — different engine, corroborates mobsfscan's secret
// rules), and trivy fs (SCA over the bundled dependency manifests). This
// is why mobile is its own asset rather than a repository sub-mode: the
// audience (mobile-app teams), the tool set, and the bench are mobile-specific.
package mobile

import (
	"context"

	"github.com/ClatTribe/tsengine/internal/asset"
	"github.com/ClatTribe/tsengine/internal/asset/common"
	"github.com/ClatTribe/tsengine/internal/tool"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// WorkspacePath is the in-sandbox mount point for the scanned app bundle.
// The CLI mounts the user's --target here read-only.
const WorkspacePath = "/workspace"

// Handler implements asset.Handler for mobile_application targets.
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

func (*Handler) Type() types.AssetType { return types.AssetMobileApplication }

func (h *Handler) Anchors() []tool.Tool  { return h.anchors }
func (h *Handler) Registry() []tool.Tool { return h.registry }

// PlanAnchors targets the in-sandbox workspace mount for every tool.
// trivy needs mode=fs to scan a directory tree (the app's bundled
// dependency manifests); mobsfscan + gitleaks take the path directly.
func (h *Handler) PlanAnchors(_ types.Asset) []asset.Dispatch {
	out := make([]asset.Dispatch, 0, len(h.anchors))
	for _, t := range h.anchors {
		args := tool.Args{"target": WorkspacePath}
		if t.Name() == "trivy" {
			args["mode"] = "fs"
		}
		out = append(out, asset.Dispatch{Tool: t, Args: args})
	}
	return out
}

// Filter is a no-op: the anchors scan the whole bundle wholesale (the
// per-tool exclude wiring lives in the wrappers). The hook stays so the
// pipeline shape matches the other assets.
func (h *Handler) Filter(_ context.Context, _ types.Asset, in []asset.Dispatch) []asset.Dispatch {
	return in
}

func (h *Handler) Normalize(results []tool.Result) []types.Finding {
	return common.Normalize(results)
}

// anchorNames: mobile SAST (mobsfscan — Android/iOS insecure-storage,
// weak-crypto, exported-component, WebView, deep-link rules), hardcoded
// secrets (gitleaks — different engine, corroborates mobsfscan's secret
// rules), and SCA over bundled dependency manifests (trivy fs). All three
// are already baked into the sandbox image (shared with repository), so
// the mobile asset adds no new sandbox tool — only a focused, mobile-first
// routing of existing wrappers.
var anchorNames = []string{
	"mobsfscan",
	"gitleaks",
	"trivy",
}

// registryNames: on-demand mobile depth surfaced via the tool-replay API.
// semgrep with mobile-language packs (Kotlin/Swift/Java) and trufflehog
// (deep verified-secret scan) are wrapped + in-image today; apkid (packer
// / obfuscator fingerprint) and a full MobSF dynamic pass are the
// documented next additions.
var registryNames = []string{
	"semgrep",
	"trufflehog",
}
