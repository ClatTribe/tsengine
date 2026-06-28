package web

import (
	"net/url"
	"sort"
	"strings"

	"github.com/ClatTribe/tsengine/internal/asset"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// SelectSurface implements asset.SurfaceSelector — the "richer than dedupe"
// surface pipeline, run BEFORE the cap (the fix for the WAVSEP no-budget bug):
//
//  1. filterSurface: scope → static-asset drop → destructive drop →
//     shape-dedup (collapse /items/1≡/items/N to one representative).
//  2. prioritize: stable-sort by value score so the highest-value endpoints
//     survive the cap (param-bearing ≫ login ≫ deep ≫ bare root).
//  3. cap: keep the top `max`.
//
// So the budget holds `max` real, in-scope, DISTINCT, high-value endpoints —
// not the first `max` raw crawl hits (which are polluted with CSS/JS/nav).
func (h *Handler) SelectSurface(target types.Asset, raw []string, max int) []string {
	// Preserve API-spec markers: openapi_spec_ingest emits "SPEC <url>" entries, which
	// are NOT URLs — filterSurface would drop them. PlanFanout routes them to the
	// spec-driven api fuzzer (schemathesis), so pull them aside, filter/prioritize/cap
	// the real URLs, then prepend the markers back (they're cheap + must survive the cap).
	var specMarkers, urls []string
	for _, e := range raw {
		if strings.HasPrefix(e, openapiSpecMarker+" ") {
			specMarkers = append(specMarkers, e)
		} else {
			urls = append(urls, e)
		}
	}
	clean := filterSurface(target, urls)
	prioritizeSurface(clean)
	if max > 0 && len(clean) > max {
		clean = clean[:max]
	}
	return append(specMarkers, clean...)
}

var _ asset.SurfaceSelector = (*Handler)(nil)

// prioritizeSurface stable-sorts in place by descending value score. Stable
// so equal-score URLs keep crawl order — deterministic for reproducibility
// (§10).
func prioritizeSurface(urls []string) {
	sort.SliceStable(urls, func(i, j int) bool {
		return scoreURL(urls[i]) > scoreURL(urls[j])
	})
}

// scoreURL ranks a URL by how much detection value it carries. The dominant
// signal is a query parameter — that's the injection point sqlmap/dalfox need
// and the bulk of WAVSEP's cases; a param URL must outrank a paramless page.
func scoreURL(rawURL string) int {
	u, err := url.Parse(rawURL)
	if err != nil {
		return 0
	}
	score := 0
	if u.RawQuery != "" {
		score += 8 // injection surface — the highest-value signal
	}
	if loginPathPattern.MatchString(u.Path) {
		score += 3 // auth endpoints: default-cred / authz interest
	}
	// Deeper paths are more specific endpoints than the bare root; bounded
	// so depth never dominates the param signal.
	depth := strings.Count(strings.Trim(u.Path, "/"), "/")
	if depth > 3 {
		depth = 3
	}
	score += depth
	return score
}
