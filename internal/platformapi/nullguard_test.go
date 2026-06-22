package platformapi

import (
	"net/http"
	"strings"
	"testing"
)

// TestGETEndpoints_NoNullArrays is the permanent regression guard for the nil-slice → JSON-null
// crash class (the bug behind #341 approvals + #342 trust-frameworks): a Go nil slice/map without
// omitempty serializes as JSON `null`, and a `null` reaching `.map`/`.filter`/`.length` in a Server
// Component white-screens the page. respond() coerces TOP-LEVEL nil slices, but an object-wrapped
// handler (writeJSON with an inner array/map) must init each inner field non-nil itself.
//
// On a FRESH tenant every collection is empty — the exact condition that exposes nil-vs-[]. We hit
// every dashboard GET and assert the JSON body carries no `:null`, so any future handler that forgets
// to initialize an inner array (or drop omitempty) fails loudly here instead of in a customer's browser.
func TestGETEndpoints_NoNullArrays(t *testing.T) {
	h, _ := setup(t) // tenant "t1", no findings/issues/incidents/... — every list is empty

	// Every authenticated GET a post-login page loads on render. Path-param routes use a valid
	// value (a non-existent pentest id / a real framework) so the handler still builds a response.
	endpoints := []string{
		"/v1/findings",
		"/v1/assets",
		"/v1/connections",
		"/v1/tenant",
		"/v1/settings/llm",
		"/v1/settings/pr-bot",
		"/v1/ai-bom",
		"/v1/trust-link",
		"/v1/approvals",
		"/v1/incidents",
		"/v1/attack-paths",
		"/v1/issues",
		"/v1/issues?show=ignored",
		"/v1/triage-funnel",
		"/v1/exclusions",
		"/v1/runtime/events",
		"/v1/engagements",
		"/v1/pentest",
		"/v1/pentest/stats",
		// (/v1/compliance/{framework}/report is GRC-backed — not wired in this lightweight setup;
		// its null-safety is covered by the grc package tests.)
	}
	for _, ep := range endpoints {
		rec := do(h, "GET", ep, "t1", "")
		if rec.Code != http.StatusOK {
			t.Errorf("%s: want 200, got %d (%s)", ep, rec.Code, strings.TrimSpace(rec.Body.String()))
			continue
		}
		ct := rec.Header().Get("Content-Type")
		if !strings.Contains(ct, "json") {
			continue // non-JSON deliverables (e.g. a markdown report) aren't .map'd by the UI
		}
		if body := rec.Body.String(); strings.Contains(body, ":null") {
			t.Errorf("%s returned a JSON null (frontend .map/.filter crash class — init the inner array as [] or add omitempty): %s",
				ep, body)
		}
	}
}
