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
	"github.com/ClatTribe/tsengine/internal/store"
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

// TestIngestInventory_DiffOnIngest: re-ingesting a changed account automatically detects config DRIFT
// vs the stored baseline — no separate /v1/cloud/drift call. First ingest establishes the baseline (0
// drift); the second, with a bucket flipped public, surfaces a grounded resource-became-public finding
// into the same store (→ issues/incidents/grc). This is the continuous-Detect "connect once, detect
// change" promise. Grounded (§10): the first ingest and an unchanged re-ingest both yield 0 drift.
func TestIngestInventory_DiffOnIngest(t *testing.T) {
	st := store.NewMemory()
	snaps := cloudsnap.NewMemStore()
	d := Deps{Store: st, CloudSnapshots: snaps}

	post := func(body string) map[string]any {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/v1/cloud/inventory", strings.NewReader(body))
		d.handleIngestAWSInventory(rec, req, "ten-1")
		if rec.Code != http.StatusOK {
			t.Fatalf("want 200, got %d: %s", rec.Code, rec.Body.String())
		}
		var resp map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &resp)
		return resp
	}

	// 1) baseline: the bucket is private → no baseline to diff against yet → 0 drift.
	base := post(`{"account_id":"111122223333","buckets":[{"name":"cust-data","public":false}]}`)
	if base["drift_detected"] != float64(0) {
		t.Fatalf("the first ingest has no baseline → 0 drift, got %v", base["drift_detected"])
	}

	// 2) re-ingest, unchanged → still 0 drift (grounded: no change, no finding).
	same := post(`{"account_id":"111122223333","buckets":[{"name":"cust-data","public":false}]}`)
	if same["drift_detected"] != float64(0) {
		t.Fatalf("an unchanged re-ingest must yield 0 drift, got %v", same["drift_detected"])
	}

	// 3) re-ingest with the bucket now PUBLIC → automatic resource-became-public drift.
	changed := post(`{"account_id":"111122223333","buckets":[{"name":"cust-data","public":true}]}`)
	if changed["drift_detected"] == float64(0) {
		t.Fatalf("flipping a bucket public must be detected as drift on re-ingest, got %v", changed["drift_detected"])
	}

	// the drift finding landed in the SAME store the rest of the platform reads.
	fs, err := st.ListFindings(context.Background(), "ten-1", store.FindingFilter{})
	if err != nil {
		t.Fatal(err)
	}
	var sawBecamePublic bool
	for _, f := range fs {
		if strings.Contains(f.RuleID, "clouddrift::") {
			sawBecamePublic = true
		}
	}
	if !sawBecamePublic {
		t.Errorf("expected a clouddrift:: change-control finding in the store, got %d findings", len(fs))
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

// ── AN EMPTY INVENTORY IS NOT AN EMPTY ACCOUNT ───────────────────────────────────────────────────

// The FETCH path refuses to return an empty inventory because it "would read as an account with
// nothing in it". The POSTED path accepted one — POST {"account_id":"…"} returned stored:true,
// resources:0 — so the same danger walked in through the other door.
//
// Storing it does two things. The AI Cloud Engineer reasons over the snapshot, finds no principals
// and no edges, and reports no attack paths for an account it has never seen. And the snapshot
// becomes the DRIFT BASELINE, so the next real ingest diffs against "empty" and reports every
// existing resource as newly created.
func TestIngestInventory_EmptyIsRefusedNotStored(t *testing.T) {
	snaps := cloudsnap.NewMemStore()
	d := Deps{CloudSnapshots: snaps}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/cloud/inventory",
		strings.NewReader(`{"account_id":"111122223333"}`))
	d.handleIngestAWSInventory(rec, req, "ten-empty")

	if rec.Code == http.StatusOK {
		t.Fatalf("an inventory with no resources was accepted (%s) — the account is now recorded "+
			"as empty, which the cloud engineer will read as \"nothing to find\"", rec.Body.String())
	}
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
	var body map[string]string
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if body["code"] != "empty_inventory" {
		t.Errorf("no machine-readable reason: %v", body)
	}

	// And nothing was written — a refused ingest must not leave a baseline behind.
	if _, ok, _ := snaps.Get(context.Background(), "ten-empty"); ok {
		t.Error("a refused inventory was still stored as the tenant's snapshot, so it will be the " +
			"baseline the next real sync is diffed against")
	}
}

// A REAL inventory is unaffected — the guard must not reject accounts that have something in them.
func TestIngestInventory_NonEmptyStillStores(t *testing.T) {
	snaps := cloudsnap.NewMemStore()
	d := Deps{CloudSnapshots: snaps}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/cloud/inventory",
		strings.NewReader(`{"account_id":"1","buckets":[{"name":"logs"}]}`))
	d.handleIngestAWSInventory(rec, req, "ten-real")

	if rec.Code != http.StatusOK {
		t.Fatalf("a real inventory was refused: %d %s", rec.Code, rec.Body.String())
	}
	if _, ok, _ := snaps.Get(context.Background(), "ten-real"); !ok {
		t.Error("a real inventory was not stored")
	}
}
