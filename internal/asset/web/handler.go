// Package web is the Handler implementation for the web_application
// asset type. See arch.md "web_application" for the canonical
// anchor + registry + filter matrix.
package web

import (
	"context"
	"net/url"
	"strings"

	"github.com/ClatTribe/tsengine/internal/asset"
	"github.com/ClatTribe/tsengine/internal/tool"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// Handler implements asset.Handler for web_application targets.
type Handler struct {
	anchors  []tool.Tool
	registry []tool.Tool
	seedAuth tool.Tool // nil if seed_auth isn't registered
}

// NewHandler resolves anchor + registry tool slots from the global
// tool.Registry. Tools not yet wrapped resolve to nil and are skipped
// — that lets the Handler grow as Phase 2.x ships more wrappers without
// breaking when a tool is missing in dev images.
func NewHandler() *Handler {
	h := &Handler{
		anchors:  resolveTools(anchorNames),
		registry: resolveTools(registryNames),
	}
	if sa := resolveTools([]string{"seed_auth"}); len(sa) == 1 {
		h.seedAuth = sa[0]
	}
	return h
}

// Type returns the asset type.
func (*Handler) Type() types.AssetType { return types.AssetWebApplication }

// Anchors returns the deterministic always-fire tools. See arch.md
// "web_application" matrix.
func (h *Handler) Anchors() []tool.Tool { return h.anchors }

// Registry returns the on-demand tool catalog. Surfaced via the
// tool-replay API and L2's dispatch_l2_probe.
func (h *Handler) Registry() []tool.Tool { return h.registry }

// PlanAnchors is the single-target fallback (used when katana isn't
// registered). Each anchor receives the target URL as args["target"].
func (h *Handler) PlanAnchors(target types.Asset) []asset.Dispatch {
	return asset.DefaultPlanAnchors(target, h.anchors)
}

// Recon returns the surface-discovery tools (katana). If katana isn't
// registered/installed, this is empty and the orchestrator falls back to
// the single-target PlanAnchors path.
func (h *Handler) Recon() []tool.Tool {
	// katana crawls the surface; openapi_spec_ingest probes for an OpenAPI/Swagger
	// spec. Modern web targets are frequently an API/SPA backend — when a spec is
	// found, PlanFanout routes it to the api asset's spec-driven fuzzer
	// (schemathesis), so a web scan that lands on an API gets API-aware testing the
	// crawl/fan-out tools structurally can't (their inputs live in JSON bodies /
	// dynamic-JS params, not crawlable param URLs). No spec → graceful no-op.
	return resolveTools([]string{"katana", "openapi_spec_ingest"})
}

// openapiSpecMarker mirrors internal/asset/api: openapi_spec_ingest emits a
// "SPEC <url>" surface entry when it resolves a schema. Kept in sync with the api
// handler's const (same tool, same marker).
const openapiSpecMarker = "SPEC"

// reconDepth is the crawl depth handed to katana. Depth 2 is too shallow
// to discover a real app's surface — landing pages, index/menu pages, and
// list→detail links routinely sit 3 hops from the entry point (WAVSEP's
// index → category-index → eval-index → case is the canonical example).
// Depth 3 is the realistic default; bounded by TSENGINE_FANOUT_MAX_URLS
// downstream so a deep crawl still can't explode the dispatch set.
const reconDepth = 3

// PlanRecon shapes the katana dispatch with an explicit crawl depth.
// Without this the orchestrator's DefaultPlanAnchors would dispatch katana
// with only args["target"], inheriting the wrapper's shallow depth-2
// default. (asset.ReconPlanner)
func (h *Handler) PlanRecon(target types.Asset) []asset.Dispatch {
	out := make([]asset.Dispatch, 0, 2)
	for _, t := range h.Recon() {
		args := tool.Args{"target": target.Target}
		if t.Name() == "katana" { // only katana takes a crawl depth; openapi_spec_ingest just needs the target
			args["depth"] = reconDepth
		}
		out = append(out, asset.Dispatch{Tool: t, Args: args})
	}
	return out
}

// PlanFanout shapes the detection dispatch set across the crawled
// surface. The split is deliberate (and the reason nuclei/httpx grew a
// URL-list mode):
//
//   - nuclei + httpx run ONCE over the whole surface (args["targets"] =
//     newline-joined list → -list/-l). Running them per-URL would re-run
//     the full template/probe set N times — the WAVSEP 2h+ trap.
//   - dalfox runs per-URL, but only on URLs that carry query params
//     (nothing to inject into a param-less URL). The filter's per-URL
//     routing prunes the rest.
//
// Tools other than the listed ones default to per-URL dispatch; the
// filter decides which URLs they apply to.
func (h *Handler) PlanFanout(target types.Asset, surface []string) []asset.Dispatch {
	var out []asset.Dispatch

	// API-aware routing: openapi_spec_ingest emits a "SPEC <url>" surface entry when
	// it resolves a schema on the target. Route it to the api asset's spec-driven
	// fuzzer (schemathesis) — this is how a web scan that lands on an API/SPA backend
	// gets API-aware injection/authz testing the crawl/fan-out tools can't provide.
	// Extract the markers BEFORE filterSurface (they're not URLs). No spec → no-op.
	var rest []string
	for _, e := range surface {
		if specURL, ok := strings.CutPrefix(e, openapiSpecMarker+" "); ok {
			if st, ok := tool.Get("schemathesis"); ok {
				out = append(out, asset.Dispatch{Tool: st, Args: tool.Args{"spec_url": strings.TrimSpace(specURL)}})
			}
			continue
		}
		rest = append(rest, e)
	}
	surface = rest

	// Reduce the surface first: scope, static-asset + destructive-path
	// drops, then shape-dedup (so /items/1..N collapse to one). Both the
	// list-mode tools and the per-URL tools fan out over this clean set.
	surface = filterSurface(target, surface)

	listArg := strings.Join(surface, "\n")

	// Authenticated scan: a seed_auth dispatch leads. The W3 wave
	// classifier puts it in wave 0 (the detectors depend on seed_auth);
	// the orchestrator threads the captured session into the detectors'
	// args["cookie"] in the next wave.
	if target.Auth != nil && h.seedAuth != nil {
		a := target.Auth
		out = append(out, asset.Dispatch{Tool: h.seedAuth, Args: tool.Args{
			"cookie":         a.Cookie,
			"login_url":      a.LoginURL,
			"username":       a.Username,
			"password":       a.Password,
			"username_field": a.UsernameField,
			"password_field": a.PasswordField,
		}})
	}

	// Param-bearing URLs are the injection / fuzzing surface.
	var paramURLs []string
	for _, u := range surface {
		if hasQueryParams(u) {
			paramURLs = append(paramURLs, u)
		}
	}

	// 1) List-mode tools run ONCE: nuclei signature/CVE/misconfig templates +
	//    httpx over the whole surface, AND nuclei -dast over the PARAM surface
	//    (active fuzzing: path-traversal / open-redirect / SSRF — the generic
	//    classes WAVSEP measures, which nuclei's signature templates don't
	//    catch). nuclei is LIST-NATIVE: one engine fuzzes the whole list with
	//    internal concurrency + rate-limiting. A single nuclei spawn costs
	//    ~27s of template compile, so -dast is ONE list dispatch — running it
	//    per-URL would pay that ~27s for every URL (and run N full engines at
	//    once under parallelism). Only genuinely single-target tools go
	//    per-URL (step 2).
	for _, t := range h.anchors {
		switch t.Name() {
		case "nuclei":
			out = append(out, asset.Dispatch{Tool: t, Args: tool.Args{"targets": listArg}})
			if len(paramURLs) > 0 {
				out = append(out, asset.Dispatch{Tool: t, Args: tool.Args{
					"targets": strings.Join(paramURLs, "\n"), "dast": true}})
			}
		case "httpx":
			out = append(out, asset.Dispatch{Tool: t, Args: tool.Args{"targets": listArg}})
		}
	}

	// 2) Genuinely single-target tools (sqlmap=SQLi, dalfox=XSS) fan per-URL
	//    over the param surface, interleaved by URL so a sequential / partial
	//    run covers COMPLETE URLs (both tools per URL) rather than all of one
	//    tool then none of the next.
	for _, u := range paramURLs {
		for _, t := range h.anchors {
			switch t.Name() {
			case "sqlmap", "dalfox":
				out = append(out, asset.Dispatch{Tool: t, Args: tool.Args{"target": u}})
			}
		}
	}

	// 3) Any other per-URL anchor (not list-mode, not injection) fans across
	//    the whole surface — unchanged behavior for assets with such tools.
	for _, t := range h.anchors {
		switch t.Name() {
		case "nuclei", "httpx", "sqlmap", "dalfox":
			// handled above
		default:
			for _, u := range surface {
				out = append(out, asset.Dispatch{Tool: t, Args: tool.Args{"target": u}})
			}
		}
	}
	return out
}

func hasQueryParams(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	return u.RawQuery != ""
}

// thinSurfaceThreshold: at or below this many discovered URLs, the crawl
// likely missed hidden content, so content discovery (ffuf) is worth it.
const thinSurfaceThreshold = 5

// loginPathHints mark a likely authentication endpoint (default-creds
// candidate).
var loginPathHints = []string{"/login", "/signin", "/admin", "/wp-login", "/auth", "/account/login"}

func isLoginURL(rawURL string) bool {
	low := strings.ToLower(rawURL)
	for _, h := range loginPathHints {
		if strings.Contains(low, h) {
			return true
		}
	}
	return false
}

// PlanEscalation is the web conditional-depth stage (asset.EscalationPlanner).
// Depth tools fire ONLY where a signal points, never blanket:
//
//   - param-bearing URLs → nuclei DAST/OAST (blind SSRF/XXE/RCE via
//     interactsh) ONCE over the param list (list mode, not per-URL).
//   - login URLs → nuclei `default-logins` templates ONCE over them.
//   - a thin crawl surface → ffuf content discovery on the target root
//     (find hidden paths katana's link-following missed).
func (h *Handler) PlanEscalation(target types.Asset, surface []string, _ []types.Finding) []asset.Dispatch {
	var out []asset.Dispatch
	var paramURLs, loginURLs []string
	for _, u := range surface {
		if hasQueryParams(u) {
			paramURLs = append(paramURLs, u)
		}
		if isLoginURL(u) {
			loginURLs = append(loginURLs, u)
		}
	}

	if nuc, ok := tool.Get("nuclei"); ok {
		if len(paramURLs) > 0 {
			out = append(out, asset.Dispatch{Tool: nuc, Args: tool.Args{
				"targets": strings.Join(paramURLs, "\n"), "dast": true,
			}, EscalatedFrom: "param→oast(nuclei-dast)"})
		}
		if len(loginURLs) > 0 {
			out = append(out, asset.Dispatch{Tool: nuc, Args: tool.Args{
				"targets": strings.Join(loginURLs, "\n"), "tags": "default-logins",
			}, EscalatedFrom: "login→default-logins"})
		}
	}
	if len(surface) <= thinSurfaceThreshold {
		if ff, ok := tool.Get("ffuf"); ok {
			out = append(out, asset.Dispatch{Tool: ff, Args: tool.Args{"target": target.Target},
				EscalatedFrom: "thin-surface→ffuf"})
		}
	}
	// CMS-specialist depth: if the crawl surface looks like WordPress, fire
	// wpscan on the site root — generic DAST under-covers vulnerable
	// plugins/themes, user enumeration, and exposed wp-config/db backups.
	if isWordPress(surface) {
		if wp, ok := tool.Get("wpscan"); ok {
			out = append(out, asset.Dispatch{Tool: wp, Args: tool.Args{"target": target.Target},
				EscalatedFrom: "wordpress→wpscan"})
		}
	}
	return out
}

// wordpressHints are URL fragments that reliably indicate a WordPress site
// in the crawled surface (asset paths, login, XML-RPC endpoint).
var wordpressHints = []string{"/wp-content/", "/wp-includes/", "/wp-login.php", "/wp-admin/", "/xmlrpc.php", "/wp-json/"}

// isWordPress reports whether any crawled URL carries a WordPress marker.
func isWordPress(surface []string) bool {
	for _, u := range surface {
		low := strings.ToLower(u)
		for _, h := range wordpressHints {
			if strings.Contains(low, h) {
				return true
			}
		}
	}
	return false
}

// Filter applies Q5.34-style filtration rules (URL shape dedup, scope,
// static-asset drop, login protection, per-URL tool routing). See
// filter.go for the rule implementations.
func (h *Handler) Filter(_ context.Context, target types.Asset, in []asset.Dispatch) []asset.Dispatch {
	return applyFilter(target, in)
}

// Normalize converts the per-tool ToolResults the orchestrator
// collected into canonical Findings. The tool wrappers already produce
// SandboxEmittedFindings via parseJSONL/parseAny; this step lifts those
// into Finding shape and assigns IDs.
func (h *Handler) Normalize(results []tool.Result) []types.Finding {
	return normalize(results)
}

// anchorNames is the ordered list of tools that fire on every web scan.
// As wrappers land (sqlmap, ffuf, katana, ...) add them here. Keep
// alphabetic-by-stable-name within categories so tests pin order.
//
// Cap: ~12 per asset (CLAUDE.md §4.1). Currently below cap.
var anchorNames = []string{
	"nuclei",
	"dalfox",
	"httpx",
	"sqlmap",
}

// registryNames are the on-demand tools webappsec's "investigate" button
// surfaces. They're wrapped (so the tool-replay API can dispatch them)
// but never fire from the orchestrator.
var registryNames = []string{
	// CMS-specialist DAST. wpscan fires from PlanEscalation when the surface
	// looks like WordPress (signal-gated depth), and is reachable on-demand
	// via the tool-replay API. droopescan (Drupal) + joomscan (Joomla) are
	// the documented next CMS additions.
	"wpscan",
	// nikto: classic web-server scanner (legacy CGIs, default/backup files, outdated
	// server software, missing headers) — distinct corpus from nuclei, on-demand depth.
	"nikto",
	// Phase 2.x: wapiti, jaeles, arachni, gobuster, ZAP active.
}

func resolveTools(names []string) []tool.Tool {
	out := make([]tool.Tool, 0, len(names))
	for _, n := range names {
		if t, ok := tool.Get(n); ok {
			out = append(out, t)
		}
	}
	return out
}
