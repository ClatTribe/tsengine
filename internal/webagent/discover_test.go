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

	got := discoverSurface(body)
	if got == "" {
		t.Fatal("discoverSurface returned nothing — the agent gets no lead")
	}
	// Must surface the real injection point + param + method.
	for _, want := range []string{"/jobs", "job_type", "POST", "/search", "q"} {
		if !strings.Contains(got, want) {
			t.Errorf("discoverSurface missing %q\n  got: %s", want, got)
		}
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

// TestDiscoverSurface_QuietOnNothing keeps it grounded: a body with no request surface yields no
// hint (never invents endpoints — §10).
func TestDiscoverSurface_QuietOnNothing(t *testing.T) {
	if got := discoverSurface("<html><body><p>hello world</p></body></html>"); got != "" {
		t.Errorf("discoverSurface invented a lead from a plain page: %q", got)
	}
	if got := discoverSurface(""); got != "" {
		t.Errorf("discoverSurface(empty) = %q, want empty", got)
	}
}
