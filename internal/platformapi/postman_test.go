package platformapi

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/internal/connector"
	"github.com/ClatTribe/tsengine/internal/store"
)

func TestPostmanImport_ExtractsEndpoints(t *testing.T) {
	h := NewHandler(Deps{Store: store.NewMemory(), Connectors: connector.NewRegistry(), Token: "platform-tok"})
	col := `{"info":{"name":"Acme API"},"variable":[{"key":"baseUrl","value":"https://api.acme.com"}],
		"item":[{"name":"u","request":{"method":"GET","url":"{{baseUrl}}/users"}}]}`
	rec := do(h, "POST", "/v1/import/postman", "t1", col)
	if rec.Code != 200 {
		t.Fatalf("want 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var out struct {
		Name      string   `json:"name"`
		Count     int      `json:"count"`
		Endpoints []string `json:"endpoints"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("bad json: %v", err)
	}
	if out.Name != "Acme API" || out.Count != 1 || out.Endpoints[0] != "GET https://api.acme.com/users" {
		t.Errorf("import wrong: %+v", out)
	}
}

func TestPostmanImport_EmptyIsArrayNotNull(t *testing.T) {
	h := NewHandler(Deps{Store: store.NewMemory(), Connectors: connector.NewRegistry(), Token: "platform-tok"})
	rec := do(h, "POST", "/v1/import/postman", "t1", `{"info":{"name":"empty"},"item":[]}`)
	if rec.Code != 200 {
		t.Fatalf("want 200, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `"endpoints":[]`) {
		t.Errorf("empty collection must serialize endpoints as [], got: %s", rec.Body.String())
	}
}

func TestPostmanImport_RejectsNonCollection(t *testing.T) {
	h := NewHandler(Deps{Store: store.NewMemory(), Connectors: connector.NewRegistry(), Token: "platform-tok"})
	rec := do(h, "POST", "/v1/import/postman", "t1", `{"foo":"bar"}`)
	if rec.Code != 400 {
		t.Errorf("a non-collection must be 400, got %d", rec.Code)
	}
}
