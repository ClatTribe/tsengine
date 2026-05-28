// Package domain is the Handler for the domain asset type.
// See arch.md "domain" for the canonical anchor + registry + filter
// matrix.
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

// Handler implements asset.Handler for domain targets.
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

// PlanAnchors normalizes the target to a bare apex domain (strips
// scheme + path) before handing to subfinder.
func (h *Handler) PlanAnchors(target types.Asset) []asset.Dispatch {
	apex := apexDomain(target.Target)
	out := make([]asset.Dispatch, 0, len(h.anchors))
	for _, t := range h.anchors {
		out = append(out, asset.Dispatch{Tool: t, Args: tool.Args{"target": apex}})
	}
	return out
}

// Filter: arch.md notes catch-all DNS suppression + child-asset pivot.
// Both are normalize-time concerns (annotating subdomains that resolve
// everywhere, spawning child scans) — Phase 3.x. Phase 3 is no-op.
func (h *Handler) Filter(_ context.Context, _ types.Asset, in []asset.Dispatch) []asset.Dispatch {
	return in
}

func (h *Handler) Normalize(results []tool.Result) []types.Finding {
	return common.Normalize(results)
}

// apexDomain strips scheme/path/port so subfinder gets the bare apex.
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

var anchorNames = []string{
	"subfinder",
}

var registryNames = []string{
	// Phase 3.x: amass, assetfinder, findomain, dnstwist, checkdmarc,
	// censys-cli, bbot, securitytrails-cli, crt.sh integration
}
