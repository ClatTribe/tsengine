package platformapi

import (
	"encoding/json"
	"testing"

	"github.com/ClatTribe/tsengine/internal/connector"
	"github.com/ClatTribe/tsengine/internal/store"
)

func TestRegistryReconcile_ScanPlan(t *testing.T) {
	h := NewHandler(Deps{Store: store.NewMemory(), Connectors: connector.NewRegistry(), Token: "platform-tok"})

	body := `{
	  "images": [
	    {"repo":"acme/api","tag":"1.2","digest":"sha256:aaa"},
	    {"repo":"acme/api","tag":"latest","digest":"sha256:bbb"},
	    {"repo":"acme/web","tag":"3.0","digest":"sha256:ccc"}
	  ],
	  "seen": {"acme/api:1.2":"sha256:aaa","acme/api:latest":"sha256:OLD"}
	}`
	rec := do(h, "POST", "/v1/registry/reconcile", "t1", body)
	if rec.Code != 200 {
		t.Fatalf("want 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		ToScan    []map[string]string `json:"to_scan"`
		New       int                 `json:"new"`
		Updated   int                 `json:"updated"`
		Unchanged int                 `json:"unchanged"`
		NextSeen  map[string]string   `json:"next_seen"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	// acme/web:3.0 is new, acme/api:latest changed digest → 2 to scan; acme/api:1.2 unchanged.
	if resp.New != 1 || resp.Updated != 1 || resp.Unchanged != 1 {
		t.Errorf("want new=1 updated=1 unchanged=1, got %+v", resp)
	}
	if len(resp.ToScan) != 2 {
		t.Errorf("want 2 images to scan, got %d", len(resp.ToScan))
	}
	// next_seen reflects the current registry (for the caller to persist + pass back).
	if resp.NextSeen["acme/api:latest"] != "sha256:bbb" {
		t.Errorf("next_seen should carry the current digest, got %v", resp.NextSeen)
	}
}

func TestRegistryReconcile_FirstRun(t *testing.T) {
	h := NewHandler(Deps{Store: store.NewMemory(), Connectors: connector.NewRegistry(), Token: "platform-tok"})
	// No seen state → everything scans.
	rec := do(h, "POST", "/v1/registry/reconcile", "t1", `{"images":[{"repo":"a/x","tag":"1","digest":"sha256:1"}]}`)
	var resp struct {
		New    int                 `json:"new"`
		ToScan []map[string]string `json:"to_scan"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.New != 1 || len(resp.ToScan) != 1 {
		t.Errorf("first run scans all, got new=%d toScan=%d", resp.New, len(resp.ToScan))
	}
}
