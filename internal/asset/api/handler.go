// Package api is the Handler for the api asset type. See arch.md "api"
// for the canonical anchor + registry + filter matrix.
//
// A4 turns api into a spec-ingest→fan-out asset: openapi_spec_ingest
// fetches the spec and yields the exact operation inventory (the surface),
// then PlanFanout fans schemathesis (spec-driven fuzz) + nuclei (api
// signatures) across it, with per-method routing (routing.go) ready for
// the BOLA/BFLA/mass-assignment specialists when they land.
package api

import (
	"context"
	"regexp"
	"strings"

	"github.com/ClatTribe/tsengine/internal/asset"
	"github.com/ClatTribe/tsengine/internal/asset/common"
	"github.com/ClatTribe/tsengine/internal/tool"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// Handler implements asset.Handler (+ ReconHandler, ReconPlanner) for api.
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

// PlanAnchors is the single-target fallback (no spec found): nuclei with
// api-relevant tags against the bare target.
func (h *Handler) PlanAnchors(target types.Asset) []asset.Dispatch {
	out := make([]asset.Dispatch, 0, len(h.anchors))
	for _, t := range h.anchors {
		args := tool.Args{"target": target.Target}
		if t.Name() == "nuclei" {
			args["tags"] = apiNucleiTags
		}
		out = append(out, asset.Dispatch{Tool: t, Args: args})
	}
	return out
}

// Recon returns the spec-ingest tool. Empty if not registered →
// orchestrator falls back to PlanAnchors. (asset.ReconHandler)
func (h *Handler) Recon() []tool.Tool {
	return common.ResolveTools([]string{"openapi_spec_ingest"})
}

// PlanRecon hands the API base URL to the spec-ingest tool. (ReconPlanner)
func (h *Handler) PlanRecon(target types.Asset) []asset.Dispatch {
	var out []asset.Dispatch
	for _, t := range h.Recon() {
		out = append(out, asset.Dispatch{Tool: t, Args: tool.Args{"target": target.Target}})
	}
	return out
}

// PlanFanout fans detection across the ingested operations:
//
//   - schemathesis runs ONCE against the resolved schema (spec-driven
//     fuzz) — the SPEC marker entry carries the schema URL.
//   - nuclei runs ONCE over the operation URLs (list mode, api tags).
//
// Per-method routing (routing.go) classifies each operation; the
// classification is ready for the BOLA/BFLA/mass-assignment specialists
// (Akto/ADR — not yet built). Health/spec endpoints are dropped by Filter.
func (h *Handler) PlanFanout(target types.Asset, surface []string) []asset.Dispatch {
	var out []asset.Dispatch
	var specURL string
	var endpoints []string

	for _, e := range surface {
		if strings.HasPrefix(e, openapiSpecMarker+" ") {
			specURL = strings.TrimSpace(strings.TrimPrefix(e, openapiSpecMarker+" "))
			continue
		}
		_, u, ok := splitOp(e)
		if !ok {
			continue
		}
		endpoints = append(endpoints, u)
	}

	if specURL != "" {
		if st, ok := tool.Get("schemathesis"); ok {
			out = append(out, asset.Dispatch{Tool: st, Args: tool.Args{"spec_url": specURL}})
		}
	}
	if len(endpoints) > 0 {
		if nuc, ok := tool.Get("nuclei"); ok {
			out = append(out, asset.Dispatch{Tool: nuc, Args: tool.Args{
				"targets": strings.Join(dedup(endpoints), "\n"),
				"tags":    apiNucleiTags,
			}})
		}
	}
	return out
}

// PlanEscalation is the api conditional-depth stage (asset.EscalationPlanner):
//
//   - a successfully-ingested spec → kiterunner to brute-force the
//     UNDOCUMENTED routes the spec omits (shadow/debug/old-version
//     endpoints). Fires once on the target.
//   - a /graphql endpoint in the surface → inql introspection.
//
// Depth tools fire only on the signal, never blanket.
func (h *Handler) PlanEscalation(target types.Asset, surface []string, findings []types.Finding) []asset.Dispatch {
	triggers := []asset.Trigger{
		{
			Name: "spec→kiterunner",
			Tool: "kiterunner",
			MatchFinding: func(f types.Finding) (tool.Args, bool) {
				if strings.Contains(f.RuleID, "openapi_spec_ingest::spec-found") {
					return tool.Args{"target": target.Target}, true
				}
				return nil, false
			},
		},
		{
			Name: "graphql→inql",
			Tool: "inql",
			MatchSurface: func(entry string) (tool.Args, bool) {
				_, u, ok := splitOp(entry)
				if !ok {
					return nil, false
				}
				if strings.Contains(strings.ToLower(u), "/graphql") {
					return tool.Args{"target": u}, true
				}
				return nil, false
			},
		},
	}
	return asset.EvalTriggers(triggers, surface, findings, tool.Get)
}

// Filter drops health/spec endpoints from any per-op dispatch (arch.md
// "api" filtration). List-mode dispatches (schemathesis/nuclei) carry no
// per-op "target", so they pass through untouched.
func (h *Handler) Filter(_ context.Context, _ types.Asset, in []asset.Dispatch) []asset.Dispatch {
	out := make([]asset.Dispatch, 0, len(in))
	for _, d := range in {
		if v, ok := d.Args["target"].(string); ok && healthOrSpecPathPattern.MatchString(v) {
			continue
		}
		out = append(out, d)
	}
	return out
}

func (h *Handler) Normalize(results []tool.Result) []types.Finding {
	return common.Normalize(results)
}

func dedup(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, v := range in {
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}

// openapiSpecMarker mirrors openapi.SpecMarker (kept local to avoid an
// asset→tool import for one constant).
const openapiSpecMarker = "SPEC"

// apiNucleiTags narrows nuclei's corpus to the API-relevant subset.
const apiNucleiTags = "api,graphql,jwt,oauth"

// anchorNames is the single-target fallback set (no-spec path).
var anchorNames = []string{
	"nuclei",
}

// registryNames are on-demand. kiterunner (shadow-route brute-force) +
// inql (GraphQL deep introspection) are the documented next sources; the
// BOLA/BFLA/mass-assignment authz specialists await an OSS wrapper (Akto)
// or an ADR — no strong standalone OSS exists, and §13 forbids in-house.
var registryNames = []string{
	// Phase 3.x: kiterunner, inql, akto, apiclarity, restler
}

// healthOrSpecPathPattern catches endpoints we don't want to fuzz.
var healthOrSpecPathPattern = regexp.MustCompile(`(?i)/(healthz?|metrics|ping|readyz|livez|version|favicon\.ico|api-docs|v3/api-docs|swagger(\.(json|yaml|yml))?|openapi(\.(json|yaml|yml))?)(/|\?|$)`)
