package webagent

import (
	"net/url"
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
	// Only FORM-FIELD name= (input/textarea/select/button) is a request param — NOT <meta name="viewport">
	// or <link name=…>, which are page metadata. Scoping to the field tag kills that noise class (the
	// XBEN-006 replay showed the agent chase a `?viewport=` param lifted from the viewport meta tag).
	reFormName = regexp.MustCompile("(?is)<(?:input|textarea|select|button)\\b[^>]*?\\bname\\s*=\\s*[\"']([^\"']+)")
	// the <form action="..."> POST target -- the injection SINK the agent must submit to.
	reFormAction = regexp.MustCompile("(?is)<form\\b[^>]*?\\baction\\s*=\\s*[\"']([^\"'#][^\"']*)")
	reStringify  = regexp.MustCompile("(?is)JSON\\.stringify\\(\\s*\\{([^}]{0,400})\\}")
	reObjKey     = regexp.MustCompile("[\"']?([a-zA-Z_][a-zA-Z0-9_]{1,40})[\"']?\\s*:")
)

// staticAssetRe matches URLs that are page furniture, not attack surface — skipped so the hint stays
// signal-dense (the agent doesn't need /style.css to find the SQLi).
var staticAssetRe = regexp.MustCompile(`(?i)\.(css|js|png|jpe?g|gif|svg|ico|woff2?|ttf|eot|map)(\?|$)`)

// numIDRe / uuidRe match a path segment that addresses a resource by an OBJECT ID — a pure integer or
// a UUID. Such a segment in a URL is the classic IDOR/BOLA tell: the resource is enumerable, so the
// agent should try OTHER ids to reach another user's object.
var (
	numIDRe = regexp.MustCompile(`^\d+$`)
	uuidRe  = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
)

// idorTemplate turns an endpoint that addresses a resource by an object id into a parameterized
// template (/company/1042 → /company/{id}), an IDOR/BOLA enumeration lead for the agent. Returns
// (template, true) only when a qualifying id segment sits AFTER a resource-name segment — so a bare
// /123 or a leading year like /2024/report is NOT mistaken for an object-id endpoint. Scheme+host and
// query are dropped. Grounded (§10): the endpoint is a real substring of the body; the agent verifies,
// and a finding still requires the class's indicator.
func idorTemplate(endpoint string) (string, bool) {
	p := endpoint
	if i := strings.Index(p, "://"); i >= 0 { // strip scheme://host → path
		if slash := strings.IndexByte(p[i+3:], '/'); slash >= 0 {
			p = p[i+3+slash:]
		} else {
			return "", false
		}
	}
	if q := strings.IndexAny(p, "?#"); q >= 0 {
		p = p[:q]
	}
	if !strings.HasPrefix(p, "/") {
		return "", false
	}
	segs := strings.Split(p, "/") // segs[0] == "" (leading slash)
	out := make([]string, len(segs))
	copy(out, segs)
	found := false
	for i, s := range segs {
		if s == "" || i == 0 {
			continue
		}
		if !numIDRe.MatchString(s) && !uuidRe.MatchString(s) {
			continue
		}
		prev := segs[i-1] // ORIGINAL preceding segment (never a mutated {id})
		if prev == "" || numIDRe.MatchString(prev) || uuidRe.MatchString(prev) {
			continue // require a real resource name before the id (resource/{id} shape)
		}
		out[i] = "{id}"
		found = true
	}
	if !found {
		return "", false
	}
	return strings.Join(out, "/"), true
}

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
func discoverSurface(body, base string) string {
	if body == "" {
		return ""
	}
	endpoints := map[string]bool{}
	// norm resolves a raw link to an absolute in-scope URL, dropping anchors/schemes/static assets.
	// Strips a #fragment (index.html#features and index.html#support are the SAME endpoint -- keeping
	// both floods the capped list with same-page nav anchors and crowds out real handlers).
	norm := func(u string) (string, bool) {
		u = strings.TrimSpace(u)
		if u == "" || strings.HasPrefix(u, "#") || strings.HasPrefix(u, "data:") ||
			strings.HasPrefix(u, "mailto:") || strings.HasPrefix(u, "tel:") || strings.HasPrefix(u, "javascript:") {
			return "", false
		}
		if i := strings.IndexByte(u, '#'); i >= 0 { // drop same-page fragment
			u = u[:i]
		}
		if u == "" {
			return "", false
		}
		if !strings.HasPrefix(u, "/") && !strings.HasPrefix(u, "http") {
			// RELATIVE link (post.php?id=x, send.php) — resolve against the page's OWN URL.
			if b, err := url.Parse(base); err == nil && b.Host != "" {
				if r, err := url.Parse(u); err == nil {
					u = b.ResolveReference(r).String()
				} else {
					return "", false
				}
			} else {
				return "", false
			}
		}
		if staticAssetRe.MatchString(u) {
			return "", false
		}
		if len(u) > 120 {
			u = u[:120]
		}
		return u, true
	}
	addURL := func(u string) {
		if n, ok := norm(u); ok {
			endpoints[n] = true
		}
	}
	for _, re := range []*regexp.Regexp{reFetchURL, reAxiosURL, reXHROpen, reAttrURL} {
		for _, m := range re.FindAllStringSubmatch(body, -1) {
			addURL(m[1])
		}
	}
	// Form <action> targets are the highest-signal endpoints -- they're the POST SINK the agent must
	// submit the injection to (SQLi/auth-bypass/etc.). Surface them in a DEDICATED line so a page full
	// of nav links can't crowd the real handler out of the capped endpoints list. (reAttrURL already
	// adds them to `endpoints` too; this just guarantees they're always shown + labelled.)
	formActions := map[string]bool{}
	for _, m := range reFormAction.FindAllStringSubmatch(body, -1) {
		if n, ok := norm(m[1]); ok {
			formActions[n] = true
		}
	}

	// Two param classes, kept DISTINCT because the encoding differs and the agent needs to know
	// which: form fields go in a urlencoded body, but JSON.stringify keys go in an application/json
	// body. Conflating them is exactly why the XBEN-006 agent POSTed job_type as a form field and got
	// an opaque 500 (the app does request.json()) — it had no signal the body must be JSON.
	formParams := map[string]bool{}
	for _, m := range reFormName.FindAllStringSubmatch(body, -1) {
		if k := strings.TrimSpace(m[1]); k != "" && len(k) <= 40 {
			formParams[k] = true
		}
	}
	jsonParams := map[string]bool{}
	for _, sm := range reStringify.FindAllStringSubmatch(body, -1) {
		for _, km := range reObjKey.FindAllStringSubmatch(sm[1], -1) {
			k := strings.ToLower(strings.TrimSpace(km[1]))
			if !nonParamKey[k] {
				jsonParams[km[1]] = true
			}
		}
	}

	methods := map[string]bool{}
	for _, m := range reMethod.FindAllStringSubmatch(body, -1) {
		if mt := strings.ToUpper(strings.TrimSpace(m[1])); mt != "" && mt != "GET" {
			methods[mt] = true
		}
	}

	// IDOR/BOLA leads: an endpoint that carries an object id in its path (/invoice/1042) means the
	// resource is enumerable — surface a /invoice/{id} template so the agent tries OTHER ids. Derived
	// from the real endpoints above (grounded), the concrete instance still stays in the endpoints list.
	idorTemplates := map[string]bool{}
	for u := range endpoints {
		if tmpl, ok := idorTemplate(u); ok {
			idorTemplates[tmpl] = true
		}
	}

	parts := []string{}
	if s := joinSet(formActions, 8); s != "" {
		parts = append(parts, "form action (POST submit target — the injection sink): "+s)
	}
	if s := joinSet(endpoints, 15); s != "" {
		parts = append(parts, "endpoints: "+s)
	}
	if s := joinSet(idorTemplates, 10); s != "" {
		parts = append(parts, "IDOR/BOLA candidates (object id in path — try other ids for another user's object): "+s)
	}
	if s := joinSet(jsonParams, 15); s != "" {
		// The explicit "send as application/json" is the fix for the opaque-500 dead end: the agent must
		// POST a JSON body ({"field": "..."}) with Content-Type: application/json, not a form field.
		parts = append(parts, "JSON body fields (send as application/json): "+s)
	}
	if s := joinSet(formParams, 15); s != "" {
		parts = append(parts, "form params: "+s)
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
