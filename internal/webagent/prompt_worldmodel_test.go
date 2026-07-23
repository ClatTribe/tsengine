package webagent

import (
	"strings"
	"testing"
)

// TestBuildPrompt_InjectsWorldModel: the per-turn prompt carries the structured world-model digest so the
// agent always reasons over its accumulated state (not just when it calls list_routes).
func TestBuildPrompt_InjectsWorldModel(t *testing.T) {
	cc := &Context{
		Target:  "https://app.acme.com",
		History: []Turn{{ID: "t-1", Method: "GET", URL: "https://app.acme.com/search?q=x", Status: 200}},
	}
	cc.req = NewRequester([]string{"app.acme.com"}, 50, 0)
	p := buildPrompt(cc, nil)
	if !strings.Contains(p, "TARGET MODEL") || !strings.Contains(p, "ENDPOINTS") {
		t.Fatalf("prompt must inject the structured world-model digest:\n%s", p)
	}
	if !strings.Contains(p, "/search") {
		t.Errorf("the digest should include the probed endpoint")
	}
}

// TestBuildPrompt_FallbackBeforeProbe: before any probe (no evidence), it falls back to the flat routes.
func TestBuildPrompt_FallbackBeforeProbe(t *testing.T) {
	cc := &Context{Target: "https://app.acme.com", Routes: []string{"https://app.acme.com/x"}}
	cc.req = NewRequester([]string{"app.acme.com"}, 50, 0)
	p := buildPrompt(cc, nil)
	if !strings.Contains(p, "KNOWN ROUTES") {
		t.Errorf("with no evidence yet, the prompt should fall back to KNOWN ROUTES:\n%s", p)
	}
}
