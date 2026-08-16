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

	// THE HOST ITSELF IS PART OF THE SURFACE. Endpoints above come only from operations the spec
	// DECLARES, so anything the host serves outside the spec — /.env, /.git, a backup, an admin panel
	// — was never probed. That made a spec a LIABILITY: without one, PlanAnchors scans the bare
	// target and finds those; with one, fan-out took over and the host root went unscanned.
	//
	// Caught live. A target serving /.env containing DB_PASSWORD returned a single finding — the
	// spec-ingest note — while nuclei pointed at the same host flagged it high three times over.
	//
	// This restores the rule the web asset already follows (§5.1 CollectSurface: target-always-
	// included). Filter still drops health/spec URLs, and the cap still bounds the set.
	if t := strings.TrimSpace(target.Target); t != "" {
		endpoints = append(endpoints, t)
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
// apiNucleiTags selects which nuclei templates fire against an API surface.
//
// The four protocol tags (api, graphql, jwt, oauth) describe how an API AUTHENTICATES and speaks.
// They say nothing about what it accidentally SERVES, and that omission was silent: a live scan of a
// target serving /.env with DB_PASSWORD in it returned one finding — the spec-ingest note — while
// nuclei run directly against the same URL flagged it high-severity three times over
// (laravel-env, codeigniter-env, generic-env, all tagged config,exposure).
//
// So the exposure classes are added. An API host is a web host: it leaks .env, .git, backups and
// admin panels exactly like any other, and those are among the highest-severity things a scanner
// finds. Measured on a planted target: 1 finding → 3, and zero findings on a clean endpoint at
// critical/high, so the specificity floor is untouched.
//
// This asset is the ONLY one that narrowed its ANCHOR dispatch this way — web runs the full corpus
// untagged, and ip/domain use tags for deliberate per-port routing and escalation. That made api the
// odd one out rather than the pattern.
const apiNucleiTags = "api,graphql,jwt,oauth,exposure,config,files,misconfig"

// anchorNames is the single-target fallback set (no-spec path).
var anchorNames = []string{
	"nuclei",
}

// registryNames are on-demand (the "dig deeper" replay tier, §4.2). kiterunner
// (shadow-route brute-force) + inql (GraphQL deep introspection) also fire
// automatically in PlanEscalation on their signals; exposing them here makes
// them reachable via the tool-replay API without waiting for the signal. The
// BOLA/BFLA/mass-assignment authz specialist is NOT an OSS wrapper (no strong
// standalone OSS exists, §13 forbids in-house) — it's the internal/apiauthz
// differential prober, run via POST /v1/assets/{id}/authz-test/run.
var registryNames = []string{
	"kiterunner",
	"inql",
	// Phase 3.x (await wrappers/ADR): akto, apiclarity, restler
}

// healthOrSpecPathPattern catches endpoints we don't want to fuzz.
var healthOrSpecPathPattern = regexp.MustCompile(`(?i)/(healthz?|metrics|ping|readyz|livez|version|favicon\.ico|api-docs|v3/api-docs|swagger(\.(json|yaml|yml))?|openapi(\.(json|yaml|yml))?)(/|\?|$)`)
