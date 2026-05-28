// Package ip is the Handler for the ip_address asset type.
// See arch.md "ip_address" for the canonical anchor + registry +
// filter matrix.
package ip

import (
	"context"

	"github.com/ClatTribe/tsengine/internal/asset"
	"github.com/ClatTribe/tsengine/internal/asset/common"
	"github.com/ClatTribe/tsengine/internal/tool"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// Handler implements asset.Handler for ip_address targets.
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

// PlanAnchors uses the default recipe — nmap takes target=<ip/cidr>.
// Per-port nuclei tag-routing arrives Phase 3.x.
func (h *Handler) PlanAnchors(target types.Asset) []asset.Dispatch {
	return asset.DefaultPlanAnchors(target, h.anchors)
}

// Filter: closed/filtered ports are dropped by the wrapper at parse
// time (only state="open" emits a finding), so this is a no-op today.
// Per-port nuclei tag-routing is the next filter dimension.
func (h *Handler) Filter(_ context.Context, _ types.Asset, in []asset.Dispatch) []asset.Dispatch {
	return in
}

func (h *Handler) Normalize(results []tool.Result) []types.Finding {
	return common.Normalize(results)
}

// anchorNames: nmap (port + service/version) + httpx (which ports run
// HTTP + tech fingerprint). Phase 3.x adds per-port nuclei tag-routing
// + tls_audit.
var anchorNames = []string{
	"nmap",
	"httpx",
}

var registryNames = []string{
	// naabu is wrapped (internal/tool/naabu) but registry-tier until its
	// libpcap/CGO build is wired into the image.
	// Phase 3.x: naabu, masscan, rustscan, tls_audit
}
