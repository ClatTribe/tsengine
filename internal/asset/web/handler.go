// Package web is the Handler implementation for the web_application
// asset type. See arch.md "web_application" for the canonical
// anchor + registry + filter matrix.
package web

import (
	"context"

	"github.com/ClatTribe/tsengine/internal/asset"
	"github.com/ClatTribe/tsengine/internal/tool"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// Handler implements asset.Handler for web_application targets.
type Handler struct {
	anchors  []tool.Tool
	registry []tool.Tool
}

// NewHandler resolves anchor + registry tool slots from the global
// tool.Registry. Tools not yet wrapped resolve to nil and are skipped
// — that lets the Handler grow as Phase 2.x ships more wrappers without
// breaking when a tool is missing in dev images.
func NewHandler() *Handler {
	return &Handler{
		anchors:  resolveTools(anchorNames),
		registry: resolveTools(registryNames),
	}
}

// Type returns the asset type.
func (*Handler) Type() types.AssetType { return types.AssetWebApplication }

// Anchors returns the deterministic always-fire tools. See arch.md
// "web_application" matrix.
func (h *Handler) Anchors() []tool.Tool { return h.anchors }

// Registry returns the on-demand tool catalog. Surfaced via the
// tool-replay API and L2's dispatch_l2_probe.
func (h *Handler) Registry() []tool.Tool { return h.registry }

// PlanAnchors uses the default recipe — each anchor receives the user's
// target URL as args["target"]. Once recon (katana) is wired, this
// expands into per-URL fan-out.
func (h *Handler) PlanAnchors(target types.Asset) []asset.Dispatch {
	return asset.DefaultPlanAnchors(target, h.anchors)
}

// Filter applies Q5.34-style filtration rules (URL shape dedup, scope,
// static-asset drop, login protection, per-URL tool routing). See
// filter.go for the rule implementations.
func (h *Handler) Filter(_ context.Context, target types.Asset, in []asset.Dispatch) []asset.Dispatch {
	return applyFilter(target, in)
}

// Normalize converts the per-tool ToolResults the orchestrator
// collected into canonical Findings. The tool wrappers already produce
// SandboxEmittedFindings via parseJSONL/parseAny; this step lifts those
// into Finding shape and assigns IDs.
func (h *Handler) Normalize(results []tool.Result) []types.Finding {
	return normalize(results)
}

// anchorNames is the ordered list of tools that fire on every web scan.
// As wrappers land (sqlmap, ffuf, katana, ...) add them here. Keep
// alphabetic-by-stable-name within categories so tests pin order.
//
// Cap: ~12 per asset (CLAUDE.md §4.1). Currently below cap.
var anchorNames = []string{
	"nuclei",
	"dalfox",
	"httpx",
}

// registryNames are the on-demand tools webappsec's "investigate" button
// surfaces. They're wrapped (so the tool-replay API can dispatch them)
// but never fire from the orchestrator.
var registryNames = []string{
	// Phase 2.x: wapiti, nikto, jaeles, arachni, gobuster, ZAP active.
}

func resolveTools(names []string) []tool.Tool {
	out := make([]tool.Tool, 0, len(names))
	for _, n := range names {
		if t, ok := tool.Get(n); ok {
			out = append(out, t)
		}
	}
	return out
}
