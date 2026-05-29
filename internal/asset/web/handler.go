// Package web is the Handler implementation for the web_application
// asset type. See arch.md "web_application" for the canonical
// anchor + registry + filter matrix.
package web

import (
	"context"
	"net/url"
	"strings"

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

// PlanAnchors is the single-target fallback (used when katana isn't
// registered). Each anchor receives the target URL as args["target"].
func (h *Handler) PlanAnchors(target types.Asset) []asset.Dispatch {
	return asset.DefaultPlanAnchors(target, h.anchors)
}

// Recon returns the surface-discovery tools (katana). If katana isn't
// registered/installed, this is empty and the orchestrator falls back to
// the single-target PlanAnchors path.
func (h *Handler) Recon() []tool.Tool {
	return resolveTools([]string{"katana"})
}

// PlanFanout shapes the detection dispatch set across the crawled
// surface. The split is deliberate (and the reason nuclei/httpx grew a
// URL-list mode):
//
//   - nuclei + httpx run ONCE over the whole surface (args["targets"] =
//     newline-joined list → -list/-l). Running them per-URL would re-run
//     the full template/probe set N times — the WAVSEP 2h+ trap.
//   - dalfox runs per-URL, but only on URLs that carry query params
//     (nothing to inject into a param-less URL). The filter's per-URL
//     routing prunes the rest.
//
// Tools other than these three (future sqlmap, ffuf, …) default to
// per-URL dispatch; the filter decides which URLs they apply to.
func (h *Handler) PlanFanout(target types.Asset, surface []string) []asset.Dispatch {
	// Reduce the surface first: scope, static-asset + destructive-path
	// drops, then shape-dedup (so /items/1..N collapse to one). Both the
	// list-mode tools and the per-URL tools fan out over this clean set.
	surface = filterSurface(target, surface)

	listArg := strings.Join(surface, "\n")
	var out []asset.Dispatch

	for _, t := range h.anchors {
		switch t.Name() {
		case "nuclei", "httpx":
			// One run over the whole surface.
			out = append(out, asset.Dispatch{Tool: t, Args: tool.Args{"targets": listArg}})
		case "dalfox":
			// Per-URL, params only (dalfox needs an injection point).
			for _, u := range surface {
				if hasQueryParams(u) {
					out = append(out, asset.Dispatch{Tool: t, Args: tool.Args{"target": u}})
				}
			}
		default:
			for _, u := range surface {
				out = append(out, asset.Dispatch{Tool: t, Args: tool.Args{"target": u}})
			}
		}
	}
	return out
}

func hasQueryParams(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	return u.RawQuery != ""
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
