// Package asset defines the per-asset Handler contract. One Handler
// impl per asset type (web_application, api, repository, container_image,
// ip_address, domain, cloud_account). Lives under internal/asset/<asset>/
// once implementations land in Phase 2/3.
//
// The Handler interface intentionally has no method for "scan this
// target" — orchestration lives in internal/orchestrator (Phase 1+).
// Handler only describes which tools fit this asset and how to filter /
// normalize them.
package asset

import (
	"context"

	"github.com/ClatTribe/tsengine/internal/tool"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// Handler is the per-asset contract. See CLAUDE.md §3 and arch.md per-asset
// matrix for the substance behind each method.
type Handler interface {
	// Type returns the asset type this Handler covers.
	Type() types.AssetType

	// Anchors returns the tools that fire deterministically on every
	// scan of this asset. CI-capped at ~12 per asset (CLAUDE.md §4.1).
	Anchors() []tool.Tool

	// Registry returns tools wrapped but available on-demand via the
	// tool-replay API (CLAUDE.md §9). Unbounded.
	Registry() []tool.Tool

	// PlanAnchors builds the per-tool argument set for this scan. Each
	// asset shapes args differently — api passes nuclei tags=api, ip
	// passes nmap port flags, container passes image refs. The default
	// recipe used by web is implemented in DefaultPlanAnchors below.
	PlanAnchors(target types.Asset) []Dispatch

	// Filter applies asset-specific filtration over a planned dispatch
	// set (URL shape-dedup for web, file-tree skip for repo, port-state
	// filter for ip, etc.). Returns the surviving Dispatches.
	Filter(ctx context.Context, target types.Asset, dispatches []Dispatch) []Dispatch

	// Normalize converts tool-specific output into canonical Findings.
	// Called by the orchestrator after each anchor tool returns.
	Normalize(raw []tool.Result) []types.Finding
}

// DefaultPlanAnchors builds one Dispatch per tool with args = {"target":
// target.Target}. Most asset Handlers use this directly; the few that
// need per-tool args (api → nuclei tags, ip → nmap flags) override.
func DefaultPlanAnchors(target types.Asset, anchors []tool.Tool) []Dispatch {
	out := make([]Dispatch, 0, len(anchors))
	for _, t := range anchors {
		out = append(out, Dispatch{
			Tool: t,
			Args: tool.Args{"target": target.Target},
		})
	}
	return out
}

// Dispatch is a planned tool execution — (tool, args) — produced by the
// orchestrator's prepass and shaped by Handler.Filter before dispatch.
type Dispatch struct {
	Tool tool.Tool
	Args tool.Args
}
