package webagent

import (
	"strings"
	"testing"
)

func TestBuildWorldModel_DerivesSurfaceFromEvidence(t *testing.T) {
	turns := []Turn{
		{ID: "t-1", Method: "GET", URL: "https://app.acme.com/search?q=x&page=2", Status: 200},
		{ID: "t-2", Method: "GET", URL: "https://app.acme.com/items/42", Status: 200},
		{ID: "t-3", Method: "GET", URL: "https://app.acme.com/items/7", Status: 200}, // same shape as t-2
		{ID: "t-4", Method: "POST", URL: "https://app.acme.com/login", Status: 200, SetCookies: []string{"session=eyJhbGciOi.SECRET.sig; Path=/; HttpOnly"}},
		{ID: "t-5", Method: "GET", URL: "https://app.acme.com/admin", Status: 403}, // blocked
		{ID: "t-6", Method: "GET", URL: "https://app.acme.com/vault", Status: 401}, // auth required
	}
	w := BuildWorldModel(turns, nil)

	// one host, reachable
	if len(w.Hosts) != 1 || !w.Hosts["app.acme.com"].Reachable {
		t.Fatalf("expected 1 reachable host, got %+v", w.Hosts)
	}
	// /items/42 and /items/7 collapse to ONE endpoint (id-normalized shape)
	if e := w.Endpoints["GET https://app.acme.com/items/:id"]; e == nil {
		t.Errorf("id-normalized endpoint missing: %v", keys(w.Endpoints))
	}
	// /search carries its query param names
	search := w.Endpoints["GET https://app.acme.com/search"]
	if search == nil || !contains(search.Params, "q") || !contains(search.Params, "page") {
		t.Errorf("search endpoint should carry params q,page: %+v", search)
	}
	// /vault is auth-required (401)
	if v := w.Endpoints["GET https://app.acme.com/vault"]; v == nil || !v.AuthRequired {
		t.Errorf("/vault should be auth-required")
	}
	// the session cookie is held (redacted)
	if len(w.Identities) != 1 || w.Identities[0].Name != "session" {
		t.Fatalf("expected 1 held session identity, got %+v", w.Identities)
	}
	// /admin is blocked (403)
	var blocked bool
	for _, a := range w.Attempts {
		if a.Outcome == "blocked" && strings.Contains(a.Endpoint, "/admin") {
			blocked = true
		}
	}
	if !blocked {
		t.Error("/admin (403) should be a blocked attempt")
	}
}

// TestBuildWorldModel_FindingsConfirmClass: a grounded Finding marks its class confirmed on its endpoint.
func TestBuildWorldModel_FindingsConfirmClass(t *testing.T) {
	turns := []Turn{{ID: "t-1", Method: "GET", URL: "https://app.acme.com/search?q=x", Status: 200}}
	findings := []Finding{{ID: "f-1", Route: "https://app.acme.com/search?q=x", Class: "sqli", Evidence: []string{"t-1"}}}
	w := BuildWorldModel(turns, findings)
	e := w.Endpoints["GET https://app.acme.com/search"]
	if e == nil || e.Tested["sqli"] != "confirmed" {
		t.Errorf("a grounded sqli finding must mark the endpoint sqli=confirmed: %+v", e)
	}
}

// TestWorldModel_Grounding: nothing appears without an evidence Turn (§10) — the model can't invent surface.
func TestWorldModel_Grounding(t *testing.T) {
	w := BuildWorldModel(nil, nil)
	if len(w.Hosts) != 0 || len(w.Endpoints) != 0 || len(w.Identities) != 0 {
		t.Errorf("empty evidence must yield an empty model, got %+v", w)
	}
}

// TestDigest_RedactsSecretsAndRenders: the digest shows a session is held but NEVER the token value.
func TestDigest_RedactsSecretsAndRenders(t *testing.T) {
	turns := []Turn{
		{ID: "t-1", Method: "GET", URL: "https://app.acme.com/a", Status: 200},
		{ID: "t-2", Method: "POST", URL: "https://app.acme.com/login", Status: 200, SetCookies: []string{"session=SUPERSECRETTOKEN123; Path=/"}},
	}
	d := BuildWorldModel(turns, nil).Digest()
	if !strings.Contains(d, "HOSTS") || !strings.Contains(d, "ENDPOINTS") || !strings.Contains(d, "SESSIONS HELD") {
		t.Errorf("digest missing sections: %q", d)
	}
	if strings.Contains(d, "SUPERSECRETTOKEN123") {
		t.Errorf("digest must NOT leak the raw session token: %q", d)
	}
}

func keys(m map[string]*WMEndpoint) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
