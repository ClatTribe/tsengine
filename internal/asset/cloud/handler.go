// Package cloud is the Handler for the cloud_account asset type.
// See CLAUDE.md §3 + arch.md "cloud_account" for the canonical
// anchor + registry + filter matrix and authentication discipline.
//
// The scan target is the cloud provider ("aws" | "gcp" | "azure").
// Scoped, short-lived credentials are forwarded into the sandbox via
// environment variables by the CLI (cmd/tsengine forwards AWS_* /
// GOOGLE_* / AZURE_* env). Credentials never touch disk inside the
// sandbox and die with the container (--rm).
package cloud

import (
	"context"

	"github.com/ClatTribe/tsengine/internal/asset"
	"github.com/ClatTribe/tsengine/internal/asset/common"
	"github.com/ClatTribe/tsengine/internal/tool"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// Handler implements asset.Handler for cloud_account targets.
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

func (*Handler) Type() types.AssetType { return types.AssetCloudAccount }

func (h *Handler) Anchors() []tool.Tool  { return h.anchors }
func (h *Handler) Registry() []tool.Tool { return h.registry }

// PlanAnchors passes the provider through as the tool target.
func (h *Handler) PlanAnchors(target types.Asset) []asset.Dispatch {
	return asset.DefaultPlanAnchors(target, h.anchors)
}

// Filter: arch.md notes service/region scoping + read-only IAM
// enforcement. Both are credential-time concerns (the CLI forwards only
// scoped creds; prowler honors the session's permissions), so the
// orchestrator-level filter is a no-op.
func (h *Handler) Filter(_ context.Context, _ types.Asset, in []asset.Dispatch) []asset.Dispatch {
	return in
}

func (h *Handler) Normalize(results []tool.Result) []types.Finding {
	return common.Normalize(results)
}

// anchorNames: prowler is the multi-cloud posture anchor. Phase 3.x adds
// scout-suite, cloudsploit, cloudquery, steampipe, parliament.
var anchorNames = []string{
	"prowler",
}

var registryNames = []string{
	// Phase 3.x: pacu (gated by explicit scope opt-in), cloudmapper, principal-mapper
}
