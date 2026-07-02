package webagent

import (
	"regexp"
	"sort"
	"strings"
)

// discover.go extracts the request SURFACE a response reveals — the endpoints, request params, and
// non-GET methods embedded in a page/its JS — and hands them to the agent as a compact, deterministic
// hint. This is the recon signal the tight LLM-facing body snippet truncates away: a real injection
// point like `fetch('/jobs', {method:'POST', body: JSON.stringify({job_type: v})})` sits deep in the
// page (well past the snippet cap), so a blind agent never learns /jobs exists and falls back to
// probing params that aren't there. The extraction is GROUNDED — real substrings of the response, no
// LLM invention — and the agent uses them only as LEADS; findings still ride on deterministic
// indicators (§10). It's what a crawler/linkfinder would feed the agent, computed inline per response.

var (
	reFetchURL = regexp.MustCompile("(?i)\\bfetch\\(\\s*[\"'`]([^\"'`]+)")
	reAxiosURL = regexp.MustCompile("(?i)axios(?:\\.\\w+)?\\(\\s*[\"'`]([^\"'`]+)")
	reXHROpen  = regexp.MustCompile("(?i)\\.open\\(\\s*[\"'][A-Za-z]+[\"']\\s*,\\s*[\"'`]([^\"'`]+)")
	reAttrURL  = regexp.MustCompile("(?i)\\b(?:href|src|action|url)\\s*[:=]\\s*[\"'`]([^\"'`#][^\"'`]*)")
	reMethod   = regexp.MustCompile("(?i)\\bmethod\\s*:\\s*[\"']([A-Za-z]+)[\"']")
	reFormName = regexp.MustCompile("(?i)\\bname\\s*=\\s*[\"']([^\"']+)[\"']")
	reStringify = regexp.MustCompile("(?is)JSON\\.stringify\\(\\s*\\{([^}]{0,400})\\}")
	reObjKey   = regexp.MustCompile("[\"']?([a-zA-Z_][a-zA-Z0-9_]{1,40})[\"']?\\s*:")
)

// staticAssetRe matches URLs that are page furniture, not attack surface — skipped so the hint stays
// signal-dense (the agent doesn't need /style.css to find the SQLi).
var staticAssetRe = regexp.MustCompile(`(?i)\.(css|js|png|jpe?g|gif|svg|ico|woff2?|ttf|eot|map)(\?|$)`)

// nonParamKey filters JS/JSON object keys that are language furniture (fetch options, etc.), not
// request parameters — keeps the params list to plausible inputs like job_type / username.
var nonParamKey = map[string]bool{
	"method": true, "headers": true, "body": true, "mode": true, "cache": true,
	"credentials": true, "redirect": true, "referrer": true, "content": true,
	"type": true, "function": true, "return": true, "var": true, "let": true,
	"const": true, "if": true, "else": true, "for": true, "while": true, "http": true,
	"https": true, "true": true, "false": true, "null": true, "this": true,
}

// discoverSurface returns a one-line "DISCOVERED …" summary of the endpoints / request params /
// non-GET methods the body reveals, or "" when it reveals nothing useful. Output is deduped, sorted
// (stable), and length-bounded so it can't bloat the prompt.
func discoverSurface(body string) string {
	if body == "" {
		return ""
	}
	endpoints := map[string]bool{}
	addURL := func(u string) {
		u = strings.TrimSpace(u)
		// keep only same-app request paths / absolute URLs; skip anchors, data:, mailto:, static assets
		if u == "" || strings.HasPrefix(u, "#") || strings.HasPrefix(u, "data:") ||
			strings.HasPrefix(u, "mailto:") || strings.HasPrefix(u, "javascript:") {
			return
		}
		if !strings.HasPrefix(u, "/") && !strings.HasPrefix(u, "http") {
			return
		}
		if staticAssetRe.MatchString(u) {
			return
		}
		if len(u) > 120 {
			u = u[:120]
		}
		endpoints[u] = true
	}
	for _, re := range []*regexp.Regexp{reFetchURL, reAxiosURL, reXHROpen, reAttrURL} {
		for _, m := range re.FindAllStringSubmatch(body, -1) {
			addURL(m[1])
		}
	}

	params := map[string]bool{}
	for _, m := range reFormName.FindAllStringSubmatch(body, -1) {
		if k := strings.TrimSpace(m[1]); k != "" && len(k) <= 40 {
			params[k] = true
		}
	}
	// request-body keys — the JSON payload a fetch/XHR posts (where job_type lives)
	for _, sm := range reStringify.FindAllStringSubmatch(body, -1) {
		for _, km := range reObjKey.FindAllStringSubmatch(sm[1], -1) {
			k := strings.ToLower(strings.TrimSpace(km[1]))
			if !nonParamKey[k] {
				params[km[1]] = true
			}
		}
	}

	methods := map[string]bool{}
	for _, m := range reMethod.FindAllStringSubmatch(body, -1) {
		if mt := strings.ToUpper(strings.TrimSpace(m[1])); mt != "" && mt != "GET" {
			methods[mt] = true
		}
	}

	parts := []string{}
	if s := joinSet(endpoints, 15); s != "" {
		parts = append(parts, "endpoints: "+s)
	}
	if s := joinSet(params, 15); s != "" {
		parts = append(parts, "request params: "+s)
	}
	if s := joinSet(methods, 6); s != "" {
		parts = append(parts, "methods seen: "+s)
	}
	if len(parts) == 0 {
		return ""
	}
	return "DISCOVERED (from response body — leads, verify them): " + strings.Join(parts, " | ")
}

// joinSet sorts a set, caps it at max entries, and comma-joins (with a "(+N more)" tail when capped).
func joinSet(set map[string]bool, max int) string {
	if len(set) == 0 {
		return ""
	}
	keys := make([]string, 0, len(set))
	for k := range set {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	extra := 0
	if len(keys) > max {
		extra = len(keys) - max
		keys = keys[:max]
	}
	out := strings.Join(keys, ", ")
	if extra > 0 {
		out += ", (+" + itoa(extra) + " more)"
	}
	return out
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}
