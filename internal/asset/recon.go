package asset

import (
	"github.com/ClatTribe/tsengine/internal/tool"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// ReconHandler is the OPTIONAL capability for assets that discover their
// surface before fanning out detection tools across it (web crawls with
// katana; api ingests an OpenAPI spec; domain enumerates subdomains).
//
// It's a separate interface, not part of Handler, so the orchestrator
// type-asserts for it — assets without a recon stage (container, repo,
// ip, cloud) need zero changes. This is the clean alternative to strix's
// monolithic anchor_prepass.py, which folded recon + fan-out + filter
// into one 3,800-line procedural file.
//
// Two-stage flow the orchestrator runs when a Handler implements this:
//
//  1. Recon() tools run first (deterministic — NOT prompt-driven; this is
//     why tsengine never hit strix's "recon-first directive ignored by
//     the model" bug, CLAUDE.md §10).
//  2. Their Result.DiscoveredURLs become the surface; PlanFanout shapes
//     the (tool × URL) dispatch set that the existing errgroup executes.
type ReconHandler interface {
	// Recon returns the surface-discovery tools (e.g. katana). Their
	// Result.DiscoveredURLs feed PlanFanout. Empty → orchestrator falls
	// back to the single-target PlanAnchors path.
	Recon() []tool.Tool

	// PlanFanout builds the detection dispatch set across the discovered
	// surface. The surface always includes the original target (the
	// orchestrator guarantees it), so a crawl that finds nothing still
	// scans the target.
	PlanFanout(target types.Asset, surface []string) []Dispatch
}

// ChildAssetExtractor is an OPTIONAL capability: a handler that derives
// downstream assets from its own findings (a domain scan → child
// web_application/ip_address assets per discovered subdomain). The CLI
// records the result in Scan.ChildAssets so webappsec spawns child scans
// instead of re-enumerating (strix's "consume, don't re-derive" lesson).
type ChildAssetExtractor interface {
	ChildAssets(findings []types.Finding) []types.ChildAsset
}

// ReconPlanner is an OPTIONAL refinement of ReconHandler: a handler that
// implements it controls how its recon tools are dispatched (crawl depth,
// seeds, …) instead of accepting the generic DefaultPlanAnchors mapping.
// The orchestrator type-asserts for it; handlers that don't implement it
// keep the single-arg target dispatch. This mirrors PlanFanout — the
// recon dispatch shape is the handler's business, not the orchestrator's.
type ReconPlanner interface {
	PlanRecon(target types.Asset) []Dispatch
}

// CollectSurface flattens DiscoveredURLs from recon results, dedupes
// (preserving first-seen order), guarantees the original target is
// present, and caps the result. The cap bounds fan-out cost — strix's
// unbounded WAVSEP fan-out ran for hours (Q5.34l); a cap keeps a runaway
// crawl from exploding the dispatch set.
func CollectSurface(target string, results []tool.Result, max int) []string {
	if max <= 0 {
		max = 200
	}
	seen := map[string]struct{}{}
	out := make([]string, 0, max)

	add := func(u string) {
		if u == "" {
			return
		}
		if _, dup := seen[u]; dup {
			return
		}
		seen[u] = struct{}{}
		out = append(out, u)
	}

	// Original target first — always scanned even if recon is empty.
	add(target)
	for _, r := range results {
		for _, u := range r.DiscoveredURLs {
			if len(out) >= max {
				return out
			}
			add(u)
		}
	}
	return out
}
