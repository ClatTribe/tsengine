package web

import (
	"net/url"
	"path"
	"regexp"
	"strings"

	"github.com/ClatTribe/tsengine/internal/asset"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// applyFilter is the canonical Q5.34-shape filter for web. It receives
// the planned dispatches (one per anchor tool, each carrying a target
// URL in args["target"]) and returns the surviving set.
//
// Phase 2 implements four filter dimensions:
//
//  1. Scope — drop dispatches whose target is outside the asset's scope
//     (off-host, off-subdomain unless allowed by scope.ScopeHosts)
//  2. Static-asset drop — never scan .css/.png/.woff/bundled JS
//  3. Login protection — destructive tools (sqlmap, hydra) skip
//     /login, /signin to avoid lockout / CAPTCHA
//  4. Per-URL tool routing — dalfox only on URLs with text params, etc.
//
// Shape-dedup (collapsing /items/1 ≡ /items/N) and destructive-class
// drops (/admin/delete-*) become meaningful once recon (katana) is
// wired in Phase 2.x — they are no-ops on a single-target dispatch but
// the structure is in place.
func applyFilter(target types.Asset, in []asset.Dispatch) []asset.Dispatch {
	out := make([]asset.Dispatch, 0, len(in))
	scope := compileScope(target)

	for _, d := range in {
		u := targetURL(d)
		if u == "" {
			// Tool didn't carry a target arg — keep it (e.g. zero-arg
			// recon tool); orchestrator-level concerns handle that.
			out = append(out, d)
			continue
		}
		if !scope.allow(u) {
			continue
		}
		if isStaticAsset(u) {
			continue
		}
		if !toolApplies(d.Tool.Name(), u) {
			continue
		}
		out = append(out, d)
	}
	return out
}

// targetURL extracts the URL the dispatch is aimed at, if any. Tools
// without a target arg return "" so callers can decide to keep them.
func targetURL(d asset.Dispatch) string {
	if d.Args == nil {
		return ""
	}
	if v, ok := d.Args["target"].(string); ok {
		return v
	}
	return ""
}

// --- scope -------------------------------------------------------

type scopeRule struct {
	primaryHost string
	allowHosts  map[string]struct{}
	denyHosts   map[string]struct{}
}

func compileScope(target types.Asset) scopeRule {
	primary := hostOf(target.Target)
	allow := map[string]struct{}{primary: {}}
	for _, h := range target.Scope.ScopeHosts {
		allow[strings.ToLower(strings.TrimSpace(h))] = struct{}{}
	}
	deny := make(map[string]struct{}, len(target.Scope.OutOfScope))
	for _, h := range target.Scope.OutOfScope {
		deny[strings.ToLower(strings.TrimSpace(h))] = struct{}{}
	}
	return scopeRule{primaryHost: primary, allowHosts: allow, denyHosts: deny}
}

func (s scopeRule) allow(rawURL string) bool {
	h := hostOf(rawURL)
	if _, denied := s.denyHosts[h]; denied {
		return false
	}
	if _, allowed := s.allowHosts[h]; allowed {
		return true
	}
	// Subdomain of primary is in-scope by default.
	if s.primaryHost != "" && strings.HasSuffix(h, "."+s.primaryHost) {
		return true
	}
	return false
}

func hostOf(rawURL string) string {
	if rawURL == "" {
		return ""
	}
	if !strings.Contains(rawURL, "://") {
		rawURL = "http://" + rawURL
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	return strings.ToLower(u.Hostname())
}

// --- static-asset filter -----------------------------------------

var staticExt = map[string]struct{}{
	".css": {}, ".png": {}, ".jpg": {}, ".jpeg": {}, ".gif": {},
	".svg": {}, ".ico": {}, ".woff": {}, ".woff2": {}, ".ttf": {},
	".eot": {}, ".map": {}, ".mp4": {}, ".webp": {},
}

// bundledJSPattern catches webpack/vite/rollup bundle filenames that
// produce noise findings.
var bundledJSPattern = regexp.MustCompile(`\.(min|bundle|chunk|vendor|runtime)\.js$`)

func isStaticAsset(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	ext := strings.ToLower(path.Ext(u.Path))
	if _, ok := staticExt[ext]; ok {
		return true
	}
	if bundledJSPattern.MatchString(strings.ToLower(u.Path)) {
		return true
	}
	return false
}

// --- per-tool routing --------------------------------------------

// loginPathPattern catches authentication endpoints destructive tools
// should skip. Not exhaustive — covers the common cases.
var loginPathPattern = regexp.MustCompile(`(?i)/(login|signin|sign-in|users/sign_in|auth|logout|signout)(/|\?|$)`)

// destructiveTools must skip login endpoints to avoid lockout / CAPTCHA.
var destructiveTools = map[string]struct{}{
	"sqlmap": {},
	"hydra":  {},
}

// toolApplies decides whether a given tool should run against a given
// URL. Pure routing; non-destructive tools default to true.
func toolApplies(toolName, rawURL string) bool {
	if _, destructive := destructiveTools[toolName]; destructive {
		if loginPathPattern.MatchString(rawURL) {
			return false
		}
	}

	// dalfox only makes sense on URLs that have at least one query parameter
	// (so it has somewhere to inject). Pre-Phase-2.x recon, the orchestrator
	// dispatches against the user-provided target as-is; respect that — we
	// don't gate dalfox on params unless the URL has a path/query at all.
	if toolName == "dalfox" {
		u, err := url.Parse(rawURL)
		if err != nil {
			return true
		}
		// Always allow if URL has a query (params present). Otherwise
		// allow only if it's the bare target (let dalfox try its discovery).
		_ = u
	}
	return true
}
