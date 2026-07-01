package platformapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/internal/cloudgraph"
	"github.com/ClatTribe/tsengine/internal/cloudsnap"
)

// Posting raw AWS state maps it (grounded) into the attack-path Inventory and stores it as the tenant's
// cloud snapshot — so the AI cloud engineer reasons over the real account, not a hand-posted file.
func TestIngestAWSInventory_MapsAndStores(t *testing.T) {
	store := cloudsnap.NewMemStore()
	d := Deps{CloudSnapshots: store}

	body := `{
		"account_id": "111122223333",
		"roles": [{"arn":"arn:aws:iam::111122223333:role/admin","name":"admin","admin":true,
			"trust_policy":"{\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"AWS\":\"arn:aws:iam::111122223333:user/dev\"}}]}"}],
		"users": [{"arn":"arn:aws:iam::111122223333:user/dev","name":"dev"}],
		"buckets": [{"name":"public-logs","public":true}]
	}`
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/cloud/inventory", strings.NewReader(body))
	d.handleIngestAWSInventory(rec, req, "ten-1")

	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp["account_id"] != "111122223333" {
		t.Errorf("account_id not echoed: %v", resp["account_id"])
	}
	if resp["trust_edges"] != float64(1) {
		t.Errorf("want 1 trust edge, got %v", resp["trust_edges"])
	}
	if resp["internet_edges"] != float64(1) { // the public bucket
		t.Errorf("want 1 internet edge (public bucket), got %v", resp["internet_edges"])
	}

	// the stored snapshot must hold the mapped Inventory, ready for the cloud engineer to ingest
	snap, ok, err := store.Get(context.Background(), "ten-1")
	if err != nil || !ok {
		t.Fatalf("snapshot not stored (ok=%v err=%v)", ok, err)
	}
	inv, err := cloudgraph.ParseInventory(snap.Inventory)
	if err != nil {
		t.Fatalf("stored inventory does not parse: %v", err)
	}
	if inv.AccountID != "111122223333" || len(inv.Trusts) != 1 {
		t.Fatalf("stored inventory wrong: account=%q trusts=%d", inv.AccountID, len(inv.Trusts))
	}
	if g := cloudgraph.Ingest(inv); g.Node("arn:aws:iam::111122223333:role/admin") == nil {
		t.Error("stored inventory does not ingest the admin role")
	}
}

// ?provider=gcp routes the body through the GCP collector (impersonation → trust edge) and stores it.
func TestIngestInventory_GCPProvider(t *testing.T) {
	store := cloudsnap.NewMemStore()
	d := Deps{CloudSnapshots: store}
	body := `{"project_id":"proj-1","service_accounts":[{"email":"deploy@proj-1.iam.gserviceaccount.com","admin":true,"impersonators":["user:dev@acme.com"]}],"buckets":[{"name":"pub","public":true}]}`
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/cloud/inventory?provider=gcp", strings.NewReader(body))
	d.handleIngestAWSInventory(rec, req, "ten-1")
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp["trust_edges"] != float64(1) {
		t.Errorf("GCP impersonation should yield 1 trust edge, got %v", resp["trust_edges"])
	}
	if resp["internet_edges"] != float64(1) {
		t.Errorf("public bucket should yield 1 internet edge, got %v", resp["internet_edges"])
	}
	snap, ok, _ := store.Get(context.Background(), "ten-1")
	if !ok {
		t.Fatal("GCP inventory not stored")
	}
	if inv, _ := cloudgraph.ParseInventory(snap.Inventory); inv.Provider != "gcp" {
		t.Errorf("stored inventory provider should be gcp, got %q", inv.Provider)
	}
}

// An unknown provider is a 400, never a panic.
func TestIngestInventory_UnknownProvider400(t *testing.T) {
	d := Deps{CloudSnapshots: cloudsnap.NewMemStore()}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/cloud/inventory?provider=oracle", strings.NewReader(`{}`))
	d.handleIngestAWSInventory(rec, req, "ten-1")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("unknown provider should be 400, got %d", rec.Code)
	}
}

// No snapshot store wired → 503, never a panic.
func TestIngestAWSInventory_NoStore503(t *testing.T) {
	d := Deps{}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/cloud/inventory", strings.NewReader(`{"account_id":"1"}`))
	d.handleIngestAWSInventory(rec, req, "ten-1")
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("want 503 with no store, got %d", rec.Code)
	}
}
