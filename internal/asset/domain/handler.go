// Package domain is the Handler for the domain asset type.
// See arch.md "domain" for the canonical anchor + registry + filter
// matrix.
//
// A2 turns domain into a recon→fan-out asset: subfinder + amass + crt.sh
// enumerate subdomains from independent sources (the UNION is what lifts
// recall), then PlanFanout fans DNS-hygiene + subdomain-takeover +
// HTTP-probe detection across the discovered surface. Discovered
// subdomains also become first-class ChildAssets so webappsec spawns child
// scans instead of re-enumerating (strix's "consume, don't re-derive").
package domain

import (
	"context"
	"net/url"
	"strings"

	"github.com/ClatTribe/tsengine/internal/asset"
	"github.com/ClatTribe/tsengine/internal/asset/common"
	"github.com/ClatTribe/tsengine/internal/tool"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// Handler implements asset.Handler (+ ReconHandler, ReconPlanner,
// ChildAssetExtractor) for domain targets.
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

func (*Handler) Type() types.AssetType { return types.AssetDomain }

func (h *Handler) Anchors() []tool.Tool  { return h.anchors }
func (h *Handler) Registry() []tool.Tool { return h.registry }

// PlanAnchors is the single-target fallback (recon-empty path): just
// subfinder on the apex.
func (h *Handler) PlanAnchors(target types.Asset) []asset.Dispatch {
	apex := apexDomain(target.Target)
	out := make([]asset.Dispatch, 0, len(h.anchors))
	for _, t := range h.anchors {
		out = append(out, asset.Dispatch{Tool: t, Args: tool.Args{"target": apex}})
	}
	return out
}

// Recon returns the enumeration sources. The union of subfinder + amass +
// crt.sh maximizes subdomain recall; unregistered tools resolve to nil and
// are skipped (graceful in dev images). (asset.ReconHandler)
func (h *Handler) Recon() []tool.Tool {
	return common.ResolveTools([]string{"subfinder", "amass", "crtsh"})
}

// PlanRecon hands the bare apex to each enumerator (strip scheme/path/port).
// (asset.ReconPlanner)
func (h *Handler) PlanRecon(target types.Asset) []asset.Dispatch {
	apex := apexDomain(target.Target)
	var out []asset.Dispatch
	for _, t := range h.Recon() {
		out = append(out, asset.Dispatch{Tool: t, Args: tool.Args{"target": apex}})
	}
	return out
}

// PlanFanout fans detection across the discovered subdomains:
//
//   - checkdmarc on the apex (email-auth / DNS hygiene), once.
//   - nuclei with takeover templates over the whole surface (list mode) —
//     dangling-CNAME subdomain takeover.
//   - httpx over the surface (list mode) — which subdomains are live + tech.
func (h *Handler) PlanFanout(target types.Asset, surface []string) []asset.Dispatch {
	apex := apexDomain(target.Target)
	var out []asset.Dispatch

	if cd, ok := tool.Get("checkdmarc"); ok {
		out = append(out, asset.Dispatch{Tool: cd, Args: tool.Args{"target": apex}})
	}

	list := strings.Join(surface, "\n")
	if nuc, ok := tool.Get("nuclei"); ok {
		out = append(out, asset.Dispatch{Tool: nuc, Args: tool.Args{
			"targets": list,
			"tags":    "takeover",
		}})
	}
	if httpx, ok := tool.Get("httpx"); ok {
		out = append(out, asset.Dispatch{Tool: httpx, Args: tool.Args{"targets": list}})
	}
	return out
}

// ChildAssets turns discovered-subdomain findings into downstream targets.
// A subdomain defaults to a web_application child (the common case + what a
// security engineer would scan next); webappsec can re-classify after the
// httpx probe. Deduped by host, deterministic order.
// (asset.ChildAssetExtractor)
func (h *Handler) ChildAssets(findings []types.Finding) []types.ChildAsset {
	seen := map[string]struct{}{}
	var out []types.ChildAsset
	for _, f := range findings {
		if !strings.Contains(f.RuleID, "subdomain-found") {
			continue
		}
		host := strings.ToLower(strings.TrimSpace(f.Endpoint))
		if host == "" {
			continue
		}
		if _, dup := seen[host]; dup {
			continue
		}
		seen[host] = struct{}{}
		out = append(out, types.ChildAsset{
			Host:      host,
			AssetType: types.AssetWebApplication,
			Source:    f.Tool,
		})
	}
	return out
}

func (h *Handler) Filter(_ context.Context, _ types.Asset, in []asset.Dispatch) []asset.Dispatch {
	return in
}

func (h *Handler) Normalize(results []tool.Result) []types.Finding {
	return common.Normalize(results)
}

// apexDomain strips scheme/path/port so the enumerators get the bare apex.
func apexDomain(s string) string {
	s = strings.TrimSpace(s)
	if !strings.Contains(s, "://") {
		s = "http://" + s
	}
	u, err := url.Parse(s)
	if err != nil {
		return s
	}
	return strings.ToLower(u.Hostname())
}

// anchorNames is the single-target fallback (recon-empty path).
var anchorNames = []string{
	"subfinder",
}

var registryNames = []string{
	// Phase 3.x: assetfinder, findomain, dnstwist, censys-cli, bbot
}
