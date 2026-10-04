package platformapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/internal/cloudsnap"
	"github.com/ClatTribe/tsengine/internal/store"
)

// A tenant with an AWS account and a GCP project. Before snapshots were keyed per account, the GCP
// ingest overwrote the AWS baseline and the next AWS ingest diffed against GCP — reporting the whole,
// UNCHANGED account as newly public. Once both clouds sync on a schedule that is a false-drift flood on
// every pass, which is worse than no drift detection: it trains people to ignore the alert.
func TestIngestInventory_SecondCloudDoesNotBecomeTheFirstOnesBaseline(t *testing.T) {
	st := store.NewMemory()
	snaps := cloudsnap.NewMemStore()
	d := Deps{Store: st, CloudSnapshots: snaps}

	post := func(query, body string) map[string]any {
		t.Helper()
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/v1/cloud/inventory"+query, strings.NewReader(body))
		d.handleIngestAWSInventory(rec, req, "ten-1")
		if rec.Code != http.StatusOK {
			t.Fatalf("want 200, got %d: %s", rec.Code, rec.Body.String())
		}
		var resp map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &resp)
		return resp
	}

	aws := `{"account_id":"111122223333","buckets":[{"name":"cust-data","public":true}]}`
	gcp := `{"project_id":"proj-1","buckets":[{"name":"pub","public":true}]}`

	post("", aws)
	if r := post("?provider=gcp", gcp); r["drift_detected"] != float64(0) {
		t.Fatalf("a first GCP ingest has no GCP baseline → 0 drift, got %v", r["drift_detected"])
	}
	if r := post("", aws); r["drift_detected"] != float64(0) {
		t.Fatalf("an UNCHANGED AWS account re-ingested after a GCP ingest must yield 0 drift, got %v", r["drift_detected"])
	}

	fs, err := st.ListFindings(context.Background(), "ten-1", store.FindingFilter{})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range fs {
		if strings.Contains(f.RuleID, "clouddrift::") {
			t.Errorf("false drift finding stored: %s %s", f.RuleID, f.Endpoint)
		}
	}

	// And the reader sees both clouds, not whichever was posted last.
	m, ok, _ := snaps.Get(context.Background(), "ten-1")
	if !ok || !strings.Contains(string(m.Inventory), "cust-data") || !strings.Contains(string(m.Inventory), "pub") {
		t.Errorf("merged snapshot must carry both clouds: %s", m.Inventory)
	}
}
