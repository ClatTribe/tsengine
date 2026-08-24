package fleet

import (
	"net/url"
	"strings"

	"github.com/ClatTribe/tsengine/internal/estategraph"
	"github.com/ClatTribe/tsengine/internal/webagent"
)

// routeID is the ENDPOINT-level identity of a URL in estategraph's space: the path, query stripped
// (an endpoint is the coverage granularity — a specific parameterized request is not a distinct
// route). Findings, cleans, chunk routes, and probe turns all key through this, so they share ONE
// identity space (ADR 0030 D1) and a Clean on /search meets a Vulnerable on /search.
func routeID(raw string) string {
	return estategraph.Canonical(surfaceWeb, stripQuery(raw))
}

func stripQuery(raw string) string {
	if u, err := url.Parse(raw); err == nil {
		u.RawQuery = ""
		u.Fragment = ""
		return u.String()
	}
	if i := strings.IndexAny(raw, "?#"); i >= 0 {
		return raw[:i]
	}
	return raw
}

// classAttempted reports whether a turn carries a payload appropriate to the class — the evidence that
// the worker actually TRIED this class here, which is what a grounded Clean requires. A benign GET to
// a route does not clear it for sqli; only a sqli payload that failed to fire does. This mirrors
// webagent's own requiredIndicator discipline (structural markers, not the model's say-so), pointed at
// the attack side instead of the result side.
func classAttempted(t webagent.Turn, class string) bool {
	hay := strings.ToLower(decodedURL(t.URL) + " " + t.Payload + " " + t.Body)
	for _, m := range classMarkers[strings.ToLower(class)] {
		if strings.Contains(hay, m) {
			return true
		}
	}
	return false
}

// classMarkers are conservative injection fingerprints per class — presence means "an attempt was
// made", never "it worked" (that is a finding's job). Absent class → no Clean can be grounded.
var classMarkers = map[string][]string{
	"sqli":              {"'", "\"", " or ", " and ", "union", "sleep(", "--", "1=1"},
	"xss":               {"<script", "onerror=", "onload=", "javascript:", "<img", "<svg", "alert("},
	"path_traversal":    {"../", "..\\", "/etc/passwd", "%2e%2e", "..%2f"},
	"command_injection": {";", "|", "$(", "`", "&&", "%0a"},
	"open_redirect":     {"=http", "=//", "=%2f%2f", "\\\\"},
	"ssrf":              {"169.254", "localhost", "127.0.0.1", "metadata"},
}

func decodedURL(raw string) string {
	if d, err := url.QueryUnescape(raw); err == nil {
		return d
	}
	return raw
}

// ClaimsFromChunk turns one chunk's worker output into worldview claims (ADR 0030 Phase B):
//
//   - Vulnerable, for every grounded finding (evidence-cited, endpoint-routed).
//   - Clean, for the chunk's DECLARED (class × route) where no finding fired AND the worker really
//     attempted the class there (a class-payload turn hit the route). Evidence = those attempt turns.
//   - Inconclusive, for a declared route that was touched but never actually attempted for the class
//     (a request landed, but no class payload) — honestly "we passed through, we did not test it".
//   - Nothing, for a declared route the worker never reached — no verdict, never a fabricated clean.
//
// A chunk with no declared Class (residual/crown) grounds only Vulnerable — it was not testing a
// specific class, so it cannot clear one (§10).
func ClaimsFromChunk(chunk Chunk, findings []webagent.Finding, turns []webagent.Turn) []Claim {
	var claims []Claim
	// Worker turn IDs are per-CONTEXT (every worker restarts numbering at t-001), so in a MERGED
	// worldview two workers' evidence would collide and dedup to one — hiding a genuine second look.
	// Namespace every evidence ref by the chunk id so it is globally unique (the identity-space
	// discipline, applied to evidence): chunk-0002/t-001 ≠ chunk-0005/t-001.
	ns := func(ids []string) []string {
		out := make([]string, 0, len(ids))
		for _, id := range ids {
			out = append(out, chunk.ID+"/"+id)
		}
		return out
	}
	// Vulnerable from findings.
	vulnAt := map[string]bool{} // routeID|class that a finding already proved
	for _, f := range findings {
		ev := nonEmpty(f.Evidence)
		if len(ev) == 0 || f.Route == "" || f.Class == "" {
			continue
		}
		rid := routeID(f.Route)
		claims = append(claims, Claim{Route: rid, Class: f.Class, Verdict: Vulnerable, Evidence: ns(ev)})
		vulnAt[rid+"\x00"+f.Class] = true
	}
	if chunk.Class == "" {
		return claims // no declared class → cannot ground a Clean/Inconclusive
	}
	// Clean / Inconclusive for the chunk's declared class×routes.
	for _, raw := range chunk.Routes {
		rid := routeID(raw)
		if vulnAt[rid+"\x00"+chunk.Class] {
			continue // already Vulnerable here — no separate Clean
		}
		var attempts, touches []string
		for _, t := range turns {
			if routeID(t.URL) != rid {
				continue
			}
			touches = append(touches, t.ID)
			if classAttempted(t, chunk.Class) {
				attempts = append(attempts, t.ID)
			}
		}
		switch {
		case len(attempts) > 0:
			claims = append(claims, Claim{Route: rid, Class: chunk.Class, Verdict: Clean, Evidence: ns(attempts)})
		case len(touches) > 0:
			claims = append(claims, Claim{Route: rid, Class: chunk.Class, Verdict: Inconclusive, Evidence: ns(touches)})
			// else: route never reached → no verdict (honest silence, not a fabricated clean)
		}
	}
	return claims
}
