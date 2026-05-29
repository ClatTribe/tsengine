package openapi

import (
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
