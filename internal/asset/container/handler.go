// Package container is the Handler for the container_image asset type.
// See arch.md "container_image" for the canonical anchor + registry +
// filter matrix.
package container

import (
	"context"

	"github.com/ClatTribe/tsengine/internal/asset"
	"github.com/ClatTribe/tsengine/internal/asset/common"
	"github.com/ClatTribe/tsengine/internal/tool"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// Handler implements asset.Handler for container_image targets.
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

func (*Handler) Type() types.AssetType { return types.AssetContainerImage }

func (h *Handler) Anchors() []tool.Tool  { return h.anchors }
func (h *Handler) Registry() []tool.Tool { return h.registry }

// PlanAnchors targets the image ref. trivy needs mode=image; grype +
// dockle take the ref directly. Running trivy + grype (different CVE
// DBs) gives the L1.5 corroborator cross-source agreement.
func (h *Handler) PlanAnchors(target types.Asset) []asset.Dispatch {
	out := make([]asset.Dispatch, 0, len(h.anchors))
	for _, t := range h.anchors {
		args := tool.Args{"target": target.Target}
		if t.Name() == "trivy" {
			args["mode"] = "image"
		}
		out = append(out, asset.Dispatch{Tool: t, Args: args})
	}
	return out
}

// Filter is a no-op for container images today — the trivy invocation
// already restricts what it scans. arch.md's --ignore-base option for
// base-layer skip is Phase 3.x work; it requires per-finding annotation
// (layer attribution) which lives in normalize.
func (h *Handler) Filter(_ context.Context, _ types.Asset, in []asset.Dispatch) []asset.Dispatch {
	return in
}

func (h *Handler) Normalize(results []tool.Result) []types.Finding {
	return common.Normalize(results)
}

// anchorNames: trivy (CVE+misconfig+secret), grype (second CVE DB →
// corroboration), dockle (CIS misconfig). Phase 3.x adds syft (SBOM),
// hadolint, anchore.
var anchorNames = []string{
	"trivy",
	"grype",
	"dockle",
}

var registryNames = []string{
	// Phase 3.x: syft, anchore, clair, kube-bench, falco-rules
}
