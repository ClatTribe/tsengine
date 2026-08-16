package openapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/internal/tool"
)

func TestParseSpec_V3Servers(t *testing.T) {
	blob := []byte(`{
	  "openapi":"3.0.0",
	  "servers":[{"url":"https://api.example.com/v2"}],
	  "paths":{
	    "/users/{id}":{"get":{},"delete":{}},
	    "/login":{"post":{}}
	  }
	}`)
	ops := parseSpec(blob, "https://ignored")
	want := map[string]bool{
		"DELETE https://api.example.com/v2/users/{id}": true,
		"GET https://api.example.com/v2/users/{id}":    true,
		"POST https://api.example.com/v2/login":        true,
	}
	if len(ops) != len(want) {
		t.Fatalf("ops = %v, want %d", ops, len(want))
	}
	for _, o := range ops {
		if !want[o] {
			t.Errorf("unexpected op %q", o)
		}
	}
	// Sorted (deterministic).
	for i := 1; i < len(ops); i++ {
		if ops[i-1] > ops[i] {
			t.Errorf("not sorted: %v", ops)
		}
	}
}

func TestParseSpec_V2BasePathFallsBackToTarget(t *testing.T) {
	blob := []byte(`{"swagger":"2.0","basePath":"/api","paths":{"/ping":{"get":{}}}}`)
	ops := parseSpec(blob, "http://localhost:8080")
	if len(ops) != 1 || ops[0] != "GET http://localhost:8080/api/ping" {
		t.Fatalf("ops = %v, want v2 basePath joined to target", ops)
	}
}

func TestParseSpec_IgnoresNonMethods(t *testing.T) {
	// "parameters" / "summary" siblings under a path are not HTTP methods.
	blob := []byte(`{"paths":{"/x":{"get":{},"parameters":[],"summary":"hi"}}}`)
	ops := parseSpec(blob, "http://h")
	if len(ops) != 1 || !strings.HasPrefix(ops[0], "GET ") {
		t.Fatalf("ops = %v, want only the GET op", ops)
	}
}

func TestOpenAPI_Identity(t *testing.T) {
	o := New()
	if o.Name() != "openapi_spec_ingest" || !o.SandboxExecution() {
		t.Error("identity wrong")
	}
	if _, ok := tool.Get("openapi_spec_ingest"); !ok {
		t.Error("openapi_spec_ingest not registered")
	}
}

// TestRun_TargetIsItselfTheSpec pins the failure measured live against VAmPI.
//
// Only target+commonSpecPaths were tried, so pointing the api asset at an OpenAPI URL — exactly what
// fixtures/api/vampi/fixture.json documents as the target — fetched ".../openapi.json/openapi.json"
// and every other combination, all 404. The tool then returned "no spec found" successfully, so the
// surface was empty, PlanFanout saw specURL == "" and never dispatched schemathesis, and the api
// asset silently degraded to a bare nuclei scan: 0 findings, partial=false.
func TestRun_TargetIsItselfTheSpec(t *testing.T) {
	spec := `{"openapi":"3.0.0","paths":{"/users":{"get":{}},"/books":{"post":{}}}}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/openapi.json" {
			_, _ = w.Write([]byte(spec))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	res, err := (&OpenAPI{}).Run(context.Background(), tool.Args{"target": srv.URL + "/openapi.json"})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(res.DiscoveredURLs) == 0 {
		t.Fatal("no surface: the spec URL was the target and was never tried directly, so " +
			"schemathesis would never fire and the asset degrades to a bare nuclei scan")
	}
	if !strings.HasPrefix(res.DiscoveredURLs[0], SpecMarker+" ") {
		t.Errorf("surface must lead with the %q marker, got %q", SpecMarker, res.DiscoveredURLs[0])
	}
	if len(res.DiscoveredURLs) != 3 { // marker + 2 operations
		t.Errorf("expected marker + 2 operations, got %d: %v", len(res.DiscoveredURLs), res.DiscoveredURLs)
	}
}

// A 200 is not a spec. fetch() already drops non-JSON, so the case that reaches looksLikeSpec is a
// body that IS valid JSON but is not a schema — a JSON error payload served with 200, which plenty of
// APIs return. Accepting it yields zero operations and reproduces the silent degradation above.
func TestRun_RejectsValidJSONThatIsNotASpec(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"error":"not found","status":404}`))
	}))
	defer srv.Close()

	res, err := (&OpenAPI{}).Run(context.Background(), tool.Args{"target": srv.URL})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(res.DiscoveredURLs) != 0 {
		t.Errorf("a JSON error body served with 200 must not be accepted as a spec; got surface %v.\n"+
			"Accepting it means zero operations and a silently degraded api scan.", res.DiscoveredURLs)
	}
}
