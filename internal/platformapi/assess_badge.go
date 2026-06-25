package platformapi

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/ClatTribe/tsengine/internal/operate"
)

// assess_badge.go is the viral-loop half of the public lead-magnet: an embeddable SVG badge
// ("TensorShield · Grade A") a founder drops on their site / README / trust page as social proof for
// their OWN enterprise buyers. Every render is a branded backlink that sends other founders to /scan
// → they scan their own domain → PLG loop. Served as image/svg+xml so it works anywhere an <img>
// does. Results are cached per-domain (the badge is hit on every visitor pageview, so it must NOT
// run a live probe each time); only a cache MISS runs the assessment, and only that path is
// rate-limited (cache hits are free).

type badgeEntry struct {
	grade string
	score int
	exp   time.Time
}

type badgeCacheT struct {
	mu sync.Mutex
	m  map[string]badgeEntry
}

var badgeCache = &badgeCacheT{m: map[string]badgeEntry{}}

const badgeTTL = 6 * time.Hour

func (c *badgeCacheT) get(domain string, now time.Time) (badgeEntry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.m[domain]
	if !ok || now.After(e.exp) {
		return badgeEntry{}, false
	}
	return e, true
}

func (c *badgeCacheT) put(domain string, e badgeEntry) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.m[domain] = e
}

// gradeColor maps a grade to a shields-style color.
func gradeColor(grade string) string {
	switch grade {
	case "A", "B":
		return "#2da44e" // green
	case "C":
		return "#bf8700" // amber
	case "D", "F":
		return "#cf222e" // red
	default:
		return "#9f9f9f" // gray (unknown)
	}
}

func textWidth(s string) int { return len([]rune(s))*7 + 12 }

var svgEscaper = strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;")

// badgeSVG renders a flat shields-style two-segment badge. Pure (string in, string out).
func badgeSVG(label, message, color string) string {
	label, message = svgEscaper.Replace(label), svgEscaper.Replace(message)
	lw, mw := textWidth(label), textWidth(message)
	total := lw + mw
	lcx, mcx := lw/2, lw+mw/2 // text centers of the label + message segments
	return fmt.Sprintf(`<svg xmlns="http://www.w3.org/2000/svg" width="%d" height="20" role="img" aria-label="%s: %s">`+
		`<linearGradient id="s" x2="0" y2="100%%"><stop offset="0" stop-color="#bbb" stop-opacity=".1"/><stop offset="1" stop-opacity=".1"/></linearGradient>`+
		`<mask id="m"><rect width="%d" height="20" rx="3" fill="#fff"/></mask>`+
		`<g mask="url(#m)"><rect width="%d" height="20" fill="#555"/><rect x="%d" width="%d" height="20" fill="%s"/><rect width="%d" height="20" fill="url(#s)"/></g>`+
		`<g fill="#fff" text-anchor="middle" font-family="Verdana,DejaVu Sans,Geneva,sans-serif" font-size="11">`+
		`<text x="%d" y="15" fill="#010101" fill-opacity=".3">%s</text><text x="%d" y="14">%s</text>`+
		`<text x="%d" y="15" fill="#010101" fill-opacity=".3">%s</text><text x="%d" y="14">%s</text></g></svg>`,
		total, label, message,
		total,
		lw, lw, mw, color, total,
		lcx, label, lcx, label,
		mcx, message, mcx, message)
}

func writeBadge(w http.ResponseWriter, label, message, color string, maxAge int) {
	w.Header().Set("Content-Type", "image/svg+xml; charset=utf-8")
	w.Header().Set("Cache-Control", fmt.Sprintf("public, max-age=%d", maxAge))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(badgeSVG(label, message, color)))
}

// handleAssessBadge (PUBLIC — no bearer) serves the embeddable grade badge for a domain.
func (d Deps) handleAssessBadge(w http.ResponseWriter, r *http.Request) {
	domain := normalizeDomain(r.URL.Query().Get("domain"))
	if domain == "" {
		writeBadge(w, "TensorShield", "security", gradeColor(""), 300)
		return
	}
	now := time.Now()
	if e, ok := badgeCache.get(domain, now); ok {
		writeBadge(w, "TensorShield", "Grade "+e.grade, gradeColor(e.grade), int(badgeTTL.Seconds()))
		return
	}
	// Cache miss → run the assessment (only this path is rate-limited; a flood serves a neutral
	// badge rather than a 429, since the badge is an <img> and shouldn't show a broken image).
	if !publicAssessLimiter.allow(clientIP(r), now) {
		writeBadge(w, "TensorShield", "security", gradeColor(""), 60)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 9*time.Second)
	defer cancel()
	var dc operate.DomainConfig
	var wp webPosture
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); dc = operate.NewEmailAuth().FetchDomain(ctx, domain) }()
	go func() { defer wg.Done(); wp = probeWeb(ctx, domain) }()
	wg.Wait()
	res := assess(dc, wp)
	badgeCache.put(domain, badgeEntry{grade: res.Grade, score: res.Score, exp: now.Add(badgeTTL)})
	writeBadge(w, "TensorShield", "Grade "+res.Grade, gradeColor(res.Grade), int(badgeTTL.Seconds()))
}
