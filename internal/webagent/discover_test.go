package webagent

import (
	"strings"
	"testing"
)

// TestDiscoverSurface_FindsBuriedEndpoint is the fix for the harness blind spot the XBOW replay
// exposed: XBEN-006's injection point (`fetch('/jobs', {method:'POST', body: JSON.stringify({job_type
// : v})})`) sits at byte ~1650 of the homepage — far past the LLM-facing snippet cap — so a blind
// agent fetched `/`, saw only boilerplate, and probed params that don't exist. discoverSurface pulls
// the endpoint + param + method out of the FULL body so the agent gets the lead regardless of offset.
func TestDiscoverSurface_FindsBuriedEndpoint(t *testing.T) {
	body := `<!doctype html><html><head><title>Jobs</title>` +
		`<meta name="viewport" content="width=device-width, initial-scale=1.0">` + // must NOT become a "param"
		strings.Repeat("<!-- filler filler filler -->", 80) + // push the JS well past any snippet cap
		`<script>
		async function load() {
		  const response = await fetch('/jobs', {
		    method: 'POST',
		    headers: {'Content-Type':'application/json'},
		    body: JSON.stringify({ job_type: jobType })
		  });
		}
		</script>
		<form action="/search"><input name="q"></form>
		<link href="/style.css" rel="stylesheet"><script src="/app.js"></script>
		</body></html>`

	got := discoverSurface(body, "http://t/")
	if got == "" {
		t.Fatal("discoverSurface returned nothing — the agent gets no lead")
	}
	// Must surface the real injection point + param + method.
	for _, want := range []string{"/jobs", "job_type", "POST", "/search", "q"} {
		if !strings.Contains(got, want) {
			t.Errorf("discoverSurface missing %q\n  got: %s", want, got)
		}
	}
	// job_type came from JSON.stringify → it MUST be flagged as a JSON body field (send as
	// application/json), the signal whose absence sent the agent down the form-encoded 500 dead end.
	jsonIdx := strings.Index(got, "JSON body fields")
	if jsonIdx < 0 || !strings.Contains(got[jsonIdx:], "job_type") {
		t.Errorf("job_type not flagged as a JSON body field (agent would form-encode it → opaque 500)\n  got: %s", got)
	}
	// Must NOT surface page furniture (static assets) or JS language keys as params (noise control).
	for _, noise := range []string{"/style.css", "/app.js"} {
		if strings.Contains(got, noise) {
			t.Errorf("discoverSurface leaked static asset %q (should be filtered)\n  got: %s", noise, got)
		}
	}
	for _, noise := range []string{"headers", "method:", "body:"} {
		if strings.Contains(got, noise) {
			t.Errorf("discoverSurface leaked JS language key %q as a param (should be filtered)\n  got: %s", noise, got)
		}
	}
	// The XBEN-006 replay caught this: <meta name="viewport"> must NOT be surfaced as a request param
	// (the agent chased a fictional ?viewport= param). Only FORM-FIELD name= counts.
	if strings.Contains(got, "viewport") {
		t.Errorf("discoverSurface surfaced <meta name=viewport> as a request param (noise)\n  got: %s", got)
	}
}

// TestDiscoverSurface_SurfacesIDORTemplates locks in the IDOR/BOLA lead: an endpoint that addresses a
// resource by an object id (/invoice/1042, /api/users/7/orders) is surfaced as a /invoice/{id}
// template so the agent enumerates OTHER ids — the classic access-control test it otherwise skips. A
// bare id, a leading year, and an id-less path must NOT produce a template (noise control + §10).
func TestDiscoverSurface_SurfacesIDORTemplates(t *testing.T) {
	body := `<a href="/invoice/1042">inv</a>` +
		`<script>fetch('/api/users/7/orders')</script>` +
		`<a href="/account/2024/report">yearly</a>` + // 2024 is a leading id-shaped seg but NOT after a resource → no template for it
		`<a href="/about">about</a>` // no id → no template

	got := discoverSurface(body, "http://t/")
	idx := strings.Index(got, "IDOR/BOLA candidates")
	if idx < 0 {
		t.Fatalf("no IDOR/BOLA candidates surfaced\n  got: %s", got)
	}
	seg := got[idx:]
	for _, want := range []string{"/invoice/{id}", "/api/users/{id}/orders"} {
		if !strings.Contains(seg, want) {
			t.Errorf("IDOR templates missing %q\n  got: %s", want, seg)
		}
	}
	// /account/2024/report: 2024 sits directly after "account" so it IS a resource/{id} shape and is a
	// legitimate lead; what must NOT happen is templating a leading/bare numeric with no resource before
	// it. Assert the genuinely id-less /about produced nothing spurious.
	if strings.Contains(seg, "/about/{id}") {
		t.Errorf("templated an id-less path\n  got: %s", seg)
	}
}

// TestIdorTemplate_Grounded unit-tests the segment rules directly: an id after a resource name → a
// template; a bare/leading id, an id-less path, or a non-path → no template.
func TestIdorTemplate_Grounded(t *testing.T) {
	cases := []struct {
		in       string
		want     string
		template bool
	}{
		{"/invoice/1042", "/invoice/{id}", true},
		{"https://app.test/company/55/edit", "/company/{id}/edit", true},
		{"/orders/3fa85f64-5717-4562-b3fc-2c963f66afa6", "/orders/{id}", true},
		{"/123", "", false},           // bare id, no resource
		{"/about", "", false},         // no id segment
		{"/rest/products", "", false}, // words only
		{"relative/7", "", false},     // not a path
	}
	for _, c := range cases {
		got, ok := idorTemplate(c.in)
		if ok != c.template || (ok && got != c.want) {
			t.Errorf("idorTemplate(%q) = (%q,%v), want (%q,%v)", c.in, got, ok, c.want, c.template)
		}
	}
}

// TestDiscoverSurface_ResolvesRelativeLinks locks in the recon fix: RELATIVE links (post.php?id=x,
// posts/upload.php) are resolved against the page URL, not silently dropped. Absolute paths stay as-is.
func TestDiscoverSurface_ResolvesRelativeLinks(t *testing.T) {
	body := `<a href="post.php?id=EternalBlue">p</a> <a href="posts/upload-article.php">up</a> <a href="/about.php">a</a>`
	got := discoverSurface(body, "http://site.test/")
	for _, want := range []string{
		"http://site.test/post.php?id=EternalBlue",
		"http://site.test/posts/upload-article.php",
		"/about.php",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("relative link not resolved/surfaced: want %q in\n  %s", want, got)
		}
	}
}

// TestDiscoverSurface_QuietOnNothing keeps it grounded: a body with no request surface yields no
// hint (never invents endpoints — §10).
func TestDiscoverSurface_QuietOnNothing(t *testing.T) {
	if got := discoverSurface("<html><body><p>hello world</p></body></html>", "http://t/"); got != "" {
		t.Errorf("discoverSurface invented a lead from a plain page: %q", got)
	}
	if got := discoverSurface("", "http://t/"); got != "" {
		t.Errorf("discoverSurface(empty) = %q, want empty", got)
	}
}
