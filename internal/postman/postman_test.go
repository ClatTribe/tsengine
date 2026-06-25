package postman

import (
	"reflect"
	"testing"
)

func TestEndpoints_FlattensNestedFoldersAndResolvesVars(t *testing.T) {
	col := []byte(`{
		"info": {"name": "Acme API"},
		"variable": [{"key": "baseUrl", "value": "https://api.acme.com"}],
		"item": [
			{"name": "Users", "item": [
				{"name": "list", "request": {"method": "GET", "url": {"raw": "{{baseUrl}}/users?page=1"}}},
				{"name": "create", "request": {"method": "POST", "url": "{{baseUrl}}/users"}}
			]},
			{"name": "health", "request": {"method": "get", "url": {"host": ["{{baseUrl}}"], "path": ["healthz"]}}}
		]
	}`)
	got, err := Endpoints(col)
	if err != nil {
		t.Fatalf("Endpoints: %v", err)
	}
	if got.Name != "Acme API" {
		t.Errorf("name = %q", got.Name)
	}
	want := []string{
		"GET https://api.acme.com/healthz",
		"GET https://api.acme.com/users", // query stripped
		"POST https://api.acme.com/users",
	}
	if !reflect.DeepEqual(got.Operations, want) {
		t.Errorf("operations:\n got %v\nwant %v", got.Operations, want)
	}
}

func TestEndpoints_DedupesAndSkipsNonHTTP(t *testing.T) {
	col := []byte(`{
		"info": {"name": "x"},
		"item": [
			{"name": "a", "request": {"method": "GET", "url": "https://x/a"}},
			{"name": "a-dup", "request": {"method": "GET", "url": "https://x/a/"}},
			{"name": "ws", "request": {"method": "TRACE", "url": "https://x/ws"}}
		]
	}`)
	got, err := Endpoints(col)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Operations) != 1 || got.Operations[0] != "GET https://x/a" {
		t.Errorf("want 1 deduped GET, got %v", got.Operations)
	}
}

func TestEndpoints_UnresolvedVarLeftIntact(t *testing.T) {
	// A var from a separate Postman environment isn't in the collection — keep the op, don't guess.
	col := []byte(`{"info":{"name":"x"},"item":[{"name":"a","request":{"method":"GET","url":"{{envBase}}/ping"}}]}`)
	got, err := Endpoints(col)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Operations) != 1 || got.Operations[0] != "GET {{envBase}}/ping" {
		t.Errorf("unresolved var should stay intact, got %v", got.Operations)
	}
}

func TestEndpoints_RejectsNonCollection(t *testing.T) {
	if _, err := Endpoints([]byte(`{"foo":"bar"}`)); err == nil {
		t.Error("a non-collection object must error")
	}
	if _, err := Endpoints([]byte(`not json`)); err == nil {
		t.Error("invalid JSON must error")
	}
}

func TestEndpoints_EmptyCollectionNoError(t *testing.T) {
	got, err := Endpoints([]byte(`{"info":{"name":"empty"},"item":[]}`))
	if err != nil {
		t.Fatalf("empty collection should not error: %v", err)
	}
	if len(got.Operations) != 0 {
		t.Errorf("want 0 operations, got %v", got.Operations)
	}
}
