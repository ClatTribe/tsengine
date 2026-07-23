package webagent

import (
	"strings"
	"testing"
)

// TestListRoutes_ReturnsWorldModelDigest (P2): once the agent has probed surface, list_routes returns the
// structured world-model (endpoints + params + auth + sessions), plus any unprobed routes as a to-do list.
func TestListRoutes_ReturnsWorldModelDigest(t *testing.T) {
	cc := &Context{
		Target: "https://app.acme.com",
		Routes: []string{"https://app.acme.com/search", "https://app.acme.com/unprobed"},
		History: []Turn{
			{ID: "t-1", Method: "GET", URL: "https://app.acme.com/search?q=x", Status: 200},
			{ID: "t-2", Method: "GET", URL: "https://app.acme.com/vault", Status: 401},
		},
	}
	out := tRoutes(cc, nil)
	if !strings.Contains(out, "TARGET MODEL") || !strings.Contains(out, "ENDPOINTS") {
		t.Fatalf("list_routes should return the structured world-model: %q", out)
	}
	if !strings.Contains(out, "[auth]") {
		t.Errorf("the auth-required /vault should be flagged: %q", out)
	}
	if !strings.Contains(out, "UNPROBED ROUTES") || !strings.Contains(out, "/unprobed") {
		t.Errorf("unprobed routes should be listed as a to-do: %q", out)
	}
}

// TestListRoutes_EmptyFallback: before any probe, it falls back to the plain hint.
func TestListRoutes_EmptyFallback(t *testing.T) {
	cc := &Context{Target: "https://app.acme.com"}
	if out := tRoutes(cc, nil); !strings.Contains(out, "no routes discovered yet") {
		t.Errorf("empty engagement should give the plain hint: %q", out)
	}
}
