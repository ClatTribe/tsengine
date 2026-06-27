package platformapi

import (
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/internal/connector"
	"github.com/ClatTribe/tsengine/internal/store"
)

func TestCloudSearch_QueriesInventory(t *testing.T) {
	h := NewHandler(Deps{Store: store.NewMemory(), Connectors: connector.NewRegistry(), Token: "platform-tok"})
	body := `{
	  "inventory": {
	    "account_id": "123", "provider": "aws",
	    "resources": [
	      {"id":"s3-pub","kind":"resource","type":"aws_s3_bucket","name":"customer-data","region":"us-east-1","public":true,"sensitive":"high"},
	      {"id":"s3-priv","kind":"resource","type":"aws_s3_bucket","name":"logs","region":"us-east-1"}
	    ],
	    "grants": [{"principal":"role-admin","resource":"s3-pub"}]
	  },
	  "query": {"public": true}
	}`
	rec := do(h, "POST", "/v1/cloud/search", "t1", body)
	if rec.Code != 200 {
		t.Fatalf("want 200, got %d: %s", rec.Code, rec.Body.String())
	}
	out := rec.Body.String()
	if !strings.Contains(out, `"total":1`) || !strings.Contains(out, "s3-pub") {
		t.Errorf("only the public bucket should match, got %s", out)
	}
	if strings.Contains(out, "s3-priv") {
		t.Error("the private bucket must not be in the public-only result")
	}
	// relationship JOIN surfaced.
	if !strings.Contains(out, "role-admin") {
		t.Error("the matched bucket should carry its reached_by relationship (role-admin)")
	}
}

func TestCloudSearch_BadBodyIs400(t *testing.T) {
	h := NewHandler(Deps{Store: store.NewMemory(), Connectors: connector.NewRegistry(), Token: "platform-tok"})
	if rec := do(h, "POST", "/v1/cloud/search", "t1", `not json`); rec.Code != 400 {
		t.Errorf("bad body should 400, got %d", rec.Code)
	}
}
