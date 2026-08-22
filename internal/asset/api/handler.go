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
	"net/url"
	"regexp"
	"strconv"
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

	// INJECTION IS A FUZZING JOB, NOT A SIGNATURE ONE.
	//
	// Adding the sqli/injection tags above was necessary and not sufficient: nuclei's injection
	// templates are SIGNATURE-based — they match known product CVEs — so they find a vulnerable
	// version of a known application, never arbitrary SQLi in first-party code. Measured against
	// VAmPI, whose headline documented vulnerability is SQL injection: the tags took raw findings
	// from 1 to 12 and recall stayed at 0.000, still MISSING sqli.
	//
	// Generic injection discovery needs a tool that actually mutates parameters. The web asset has
	// done this since the fan-out landed (§5.1: injection tools run PER-URL on param-bearing URLs
	// only); api never did, so no injection payload was ever sent to an API endpoint.
	//
	// The spec is the ideal driver for it — it declares every operation and its parameters, which is
	// exactly what sqlmap needs. Restricted to param-bearing endpoints for the same reason web
	// restricts it: fanning a per-URL injection tool across a whole surface is the trap that makes a
	// scan miss its deadline, and a timed-out tool contributes nothing (Scan.ToolsFailed).
	// sqlmap needs to be TOLD which part of the URL to inject. Verified against VAmPI in the sandbox:
	// `sqlmap -u .../users/v1/name1*` detects the boolean-blind SQLi, while the raw spec form
	// `.../users/v1/{username}` does not — sqlmap reports the brace token "does not appear to be
	// dynamic" and never injects it. A query string sqlmap discovers on its own; a REST path
	// parameter it does not, so the marker is mandatory for the shape APIs actually use.
	if sq, ok := tool.Get("sqlmap"); ok {
		for _, u := range dedup(endpoints) {
			if hasInjectableParams(u) {
				out = append(out, asset.Dispatch{Tool: sq, Args: tool.Args{"target": injectionTarget(u)}})
			}
		}
	}
	return out
}

// injectionTarget rewrites a URL into the form sqlmap can act on: a path parameter gets sqlmap's "*"
// injection marker, so sqlmap tests that exact spot instead of guessing.
//
//   - a spec brace param  /users/v1/{username}  → /users/v1/name1*   (placeholder value + marker)
//   - a concrete id       /books/v1/42          → /books/v1/42*
//   - a query string      /search?q=1           → unchanged; sqlmap finds query params itself
//
// The placeholder for a brace token is a benign literal, not the brace: sqlmap first checks whether
// the marked spot is dynamic, and "{username}" is a constant string that returns the same 404 every
// time, so it is judged non-dynamic and skipped. "name1" is a value the endpoint actually resolves.
func injectionTarget(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	if len(u.Query()) > 0 {
		return rawURL // query params: sqlmap injects them without a marker
	}
	segs := strings.Split(u.Path, "/")
	for i := len(segs) - 1; i >= 0; i-- { // mark the LAST parameter-like segment
		s := segs[i]
		if s == "" {
			continue
		}
		if strings.HasPrefix(s, "{") && strings.HasSuffix(s, "}") {
			segs[i] = "name1*" // a value the endpoint resolves, plus the marker
			return rejoin(u, segs)
		}
		if _, err := strconv.Atoi(s); err == nil {
			segs[i] = s + "*"
			return rejoin(u, segs)
		}
	}
	return rawURL
}

// rejoin rebuilds scheme://host + path WITHOUT url.String()'s percent-encoding, which turns sqlmap's
// literal "*" marker into "%2A" and stops sqlmap recognising it as an injection point. The marker
// must survive verbatim into the argv, so the path is joined by hand.
func rejoin(u *url.URL, segs []string) string {
	out := u.Scheme + "://" + u.Host + strings.Join(segs, "/")
	if u.RawQuery != "" {
		out += "?" + u.RawQuery
	}
	return out
}

// hasInjectableParams reports whether a URL carries something an injection tool can mutate: a query
// string, or a REST path parameter.
//
// Path params matter here in a way they do not for web: an API expresses its inputs as
// /users/v1/{username} far more often than as ?username=, so a query-string-only test (what the web
// asset uses) would find almost nothing on a REST surface. Both the spec's own {brace} form and a
// concrete path segment that looks like an id are treated as injectable.
func hasInjectableParams(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	if len(u.Query()) > 0 {
		return true
	}
	if strings.Contains(u.Path, "{") && strings.Contains(u.Path, "}") {
		return true // spec-declared path parameter, e.g. /users/v1/{username}
	}
	for _, seg := range strings.Split(u.Path, "/") {
		if seg == "" {
			continue
		}
		// A numeric segment is a concrete object id — the canonical injectable REST parameter.
		if _, err := strconv.Atoi(seg); err == nil {
			return true
		}
	}
	return false
}

// hasOperations reports whether recon produced any callable endpoint beyond the bare target.
func hasOperations(surface []string) bool {
	for _, e := range surface {
		if strings.HasPrefix(e, openapiSpecMarker+" ") {
			continue // the spec marker is metadata, not an endpoint
		}
		if _, _, ok := splitOp(e); ok {
			return true
		}
	}
	return false
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
	// AN EMPTY SURFACE IS ITSELF A SIGNAL — the one that calls for route discovery.
	//
	// The spec→kiterunner trigger below fires when a spec WAS ingested, to find the routes the spec
	// omits. When recon found NO operations at all, there is nothing to scan and discovery is the
	// only way to obtain a surface, so the tool whose job is finding routes was gated on already
	// having them.
	//
	// Measured against OWASP crAPI, which publishes no spec at any common path (/openapi.json,
	// /swagger.json, /api-docs, /v3/api-docs all 404): the whole api asset produced ONE finding.
	// Against VAmPI, which does publish /openapi.json, the same asset produced 11-12 and detected
	// SQLi. Most real APIs look like crAPI, so the gap was invisible until the target stopped
	// flattering us.
	//
	// Gated on an EMPTY surface rather than merely "no spec", which keeps §5.3's escalation
	// invariant intact: this is a specific state, not blanket firing. An API whose operations were
	// discovered some other way already has a surface and needs no brute-forcing.
	var out []asset.Dispatch
	if !hasOperations(surface) {
		if kr, ok := tool.Get("kiterunner"); ok {
			out = append(out, asset.Dispatch{
				Tool:          kr,
				Args:          tool.Args{"target": target.Target},
				EscalatedFrom: "empty-surface→kiterunner",
			})
		}
	}

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
	out = append(out, asset.EvalTriggers(triggers, surface, findings, tool.Get)...)
	// THREAT-INFORMED PROBES (§7.1), now that something fingerprints the server. Grounded: a probe
	// is emitted only for a CVE really in the pinned corpus with a real exploitation signal, matched
	// against the product httpx actually observed. No corpus, or no observation, is a no-op.
	return append(out, common.ThreatInformedEscalation(findings)...)
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
//
// The INJECTION classes are added for the same reason, found the same way. The tag set above still
// described only how an API authenticates and what it accidentally serves — it had nothing that
// tests what the API DOES WITH INPUT. Measured against VAmPI, whose headline documented
// vulnerability is SQL injection: recall 0.000, MISSED sqli. An asset that cannot find SQLi on a
// deliberately SQL-injectable API is not scanning for injection at all.
//
// An API takes attacker-controlled input in path params, query strings and JSON bodies exactly like
// a web app, and injection is OWASP API Top 10. Narrowing to protocol + exposure tags silently
// excluded the single most-expected API vulnerability class.
//
// Kept as an explicit list rather than dropping the tag filter entirely: running nuclei's full
// corpus per API surface is what makes a scan miss its wall-clock deadline, and a timed-out tool
// contributes nothing at all (see Scan.ToolsFailed). Adding the classes is the measured fix; going
// untagged trades a known gap for a worse one.
const apiNucleiTags = "api,graphql,jwt,oauth,exposure,config,files,misconfig," +
	"sqli,injection,xss,ssrf,lfi,rce,traversal"

// anchorNames is the single-target fallback set (no-spec path).
var anchorNames = []string{
	"nuclei",
	// httpx FINGERPRINTS the server, which is the upstream half of threat-informed discovery.
	//
	// Without it this asset observed nothing about what the target RUNS, so
	// common.ObservationsFromFindings returned empty and no CVE probe could ever be grounded — the
	// engine could know a CVE is exploited in the wild against nginx, be pointed at an API served by
	// that nginx, and never look for it. CLAUDE.md §7.1 recorded api as deliberately unwired for
	// exactly this reason and named the fix as a fingerprinting anchor rather than an escalation
	// that reads nothing; this is that anchor.
	//
	// Cheap and already an anchor on web and domain: one HTTP request per target, and its
	// ToolArgs["webserver"] is a shape the observation extractor already honours.
	"httpx",
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
