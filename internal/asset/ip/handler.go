// Package ip is the Handler for the ip_address asset type.
// See arch.md "ip_address" for the canonical anchor + registry +
// filter matrix.
//
// A1 turns ip_address into a recon→fan-out asset (same machinery as web):
// naabu discovers open ports (the surface), then PlanFanout routes
// detection per-port — deep nmap service detection, httpx on HTTP-like
// ports, and nuclei with PORT-ROUTED template tags (strix iter-Q5.43:
// ~50x speedup vs. running the whole nuclei corpus against every port).
package ip

import (
	"context"

	"github.com/ClatTribe/tsengine/internal/asset"
	"github.com/ClatTribe/tsengine/internal/asset/common"
	"github.com/ClatTribe/tsengine/internal/tool"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// Handler implements asset.Handler (+ ReconHandler) for ip_address targets.
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

func (*Handler) Type() types.AssetType { return types.AssetIPAddress }

func (h *Handler) Anchors() []tool.Tool  { return h.anchors }
func (h *Handler) Registry() []tool.Tool { return h.registry }

// PlanAnchors is the single-target fallback used when naabu isn't
// registered (Recon() empty) — nmap + httpx on the bare target, the
// pre-A1 behavior.
func (h *Handler) PlanAnchors(target types.Asset) []asset.Dispatch {
	return asset.DefaultPlanAnchors(target, h.anchors)
}

// Recon returns the port-discovery tool (naabu). Empty if naabu isn't
// registered → orchestrator falls back to PlanAnchors. (asset.ReconHandler)
func (h *Handler) Recon() []tool.Tool {
	return common.ResolveTools([]string{"naabu"})
}

// PlanFanout routes detection across the discovered open ports.
//
//   - nmap runs ONCE with -sV against the discovered port set (deep
//     service/version detection) — or the bare target if recon found
//     nothing (graceful fallback == pre-A1 nmap behavior).
//   - httpx probes the HTTP-like host:port endpoints (list mode).
//   - nuclei runs PER PORT with port-routed tags (the ~50x guard).
func (h *Handler) PlanFanout(target types.Asset, surface []string) []asset.Dispatch {
	var out []asset.Dispatch
	ports := discoveredPorts(surface)

	// Deep service detection (nmap). One dispatch; pass discovered ports
	// when we have them so nmap doesn't re-scan its default range.
	if nmap, ok := tool.Get("nmap"); ok {
		args := tool.Args{"target": target.Target}
		if len(ports) > 0 {
			args["ports"] = joinPorts(ports)
		}
		out = append(out, asset.Dispatch{Tool: nmap, Args: args})
	}

	// HTTP probe (httpx) over HTTP-like endpoints — list mode, one run.
	if httpx, ok := tool.Get("httpx"); ok {
		var httpEndpoints []string
		for _, e := range surface {
			if _, p, hasPort := splitHostPort(e); hasPort && httpLikePorts[p] {
				httpEndpoints = append(httpEndpoints, e)
			}
		}
		switch {
		case len(httpEndpoints) > 0:
			out = append(out, asset.Dispatch{Tool: httpx, Args: tool.Args{
				"targets": joinLines(httpEndpoints)}})
		case len(ports) == 0:
			// Recon empty → probe the bare target (pre-A1 behavior).
			out = append(out, asset.Dispatch{Tool: httpx, Args: tool.Args{
				"target": target.Target}})
		}
	}

	// Per-port nuclei with routed tags.
	if nuc, ok := tool.Get("nuclei"); ok {
		for _, e := range surface {
			host, p, hasPort := splitHostPort(e)
			if !hasPort {
				continue
			}
			out = append(out, asset.Dispatch{Tool: nuc, Args: tool.Args{
				"target": hostPort(host, p),
				"tags":   nucleiTagsForPort(p),
			}})
		}
	}

	return out
}

func (h *Handler) Filter(_ context.Context, _ types.Asset, in []asset.Dispatch) []asset.Dispatch {
	return in
}

func (h *Handler) Normalize(results []tool.Result) []types.Finding {
	return common.Normalize(results)
}

// anchorNames is the single-target fallback set (Recon-empty path).
var anchorNames = []string{
	"nmap",
	"httpx",
}

var registryNames = []string{
	// Phase 3.x: masscan, rustscan, nessus-essentials, openvas
}
