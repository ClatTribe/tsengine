// Package api is the Handler for the api asset type. See arch.md "api"
// for the canonical anchor + registry + filter matrix.
package api

import (
	"context"
	"regexp"

	"github.com/ClatTribe/tsengine/internal/asset"
	"github.com/ClatTribe/tsengine/internal/asset/common"
	"github.com/ClatTribe/tsengine/internal/tool"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// Handler implements asset.Handler for api targets.
//
// Phase 3 anchors with nuclei using `tags=api` (the broad nuclei
// template tag for API-targeted detection). Spec-driven fuzzers
// (schemathesis, kiterunner) arrive in Phase 3.x.
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

func (*Handler) Type() types.AssetType { return types.AssetAPI }

func (h *Handler) Anchors() []tool.Tool  { return h.anchors }
func (h *Handler) Registry() []tool.Tool { return h.registry }

// PlanAnchors customizes the per-tool args for api scans. nuclei
// receives `tags=api` so its 13K-template corpus narrows to the
// API-relevant subset.
func (h *Handler) PlanAnchors(target types.Asset) []asset.Dispatch {
	out := make([]asset.Dispatch, 0, len(h.anchors))
	for _, t := range h.anchors {
		args := tool.Args{"target": target.Target}
		switch t.Name() {
		case "nuclei":
			args["tags"] = "api,graphql,jwt,oauth"
		}
		out = append(out, asset.Dispatch{Tool: t, Args: args})
	}
	return out
}

func (h *Handler) Filter(_ context.Context, _ types.Asset, in []asset.Dispatch) []asset.Dispatch {
	return applyFilter(in)
}

func (h *Handler) Normalize(results []tool.Result) []types.Finding {
	return common.Normalize(results)
}

// anchorNames is the ordered always-fire list. Phase 3.x will add
// schemathesis (Python wrapper), scan_api_bola/bfla/mass_assignment
// (in-house orchestration), kiterunner.
var anchorNames = []string{
	"nuclei",
}

// registryNames are the on-demand tools webappsec exposes via
// tool-replay. None wrapped yet.
var registryNames = []string{
	// Phase 3.x: schemathesis, kiterunner, apiclarity, restler, fuzzapi
}

// healthOrSpecPathPattern catches endpoints we don't want to fuzz —
// arch.md "api" filtration drops these to focus the scan.
var healthOrSpecPathPattern = regexp.MustCompile(`(?i)/(healthz?|metrics|ping|readyz|livez|version|favicon\.ico|api-docs|v3/api-docs|swagger(\.(json|yaml|yml))?|openapi(\.(json|yaml|yml))?)(/|\?|$)`)

func applyFilter(in []asset.Dispatch) []asset.Dispatch {
	out := make([]asset.Dispatch, 0, len(in))
	for _, d := range in {
		if v, ok := d.Args["target"].(string); ok && healthOrSpecPathPattern.MatchString(v) {
			continue
		}
		out = append(out, d)
	}
	return out
}
