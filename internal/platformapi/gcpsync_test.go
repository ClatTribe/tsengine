package platformapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ClatTribe/tsengine/internal/cloudsnap"
	"github.com/ClatTribe/tsengine/internal/connector/gcpfetch"
	"github.com/ClatTribe/tsengine/internal/connector/gcpinventory"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

type fakeGCPFetcher struct {
	res gcpfetch.Result
	err error
}

func (f fakeGCPFetcher) Fetch(context.Context) (gcpfetch.Result, error) { return f.res, f.err }

func rawGCP(t *testing.T, js string) gcpinventory.RawGCP {
	t.Helper()
	var r gcpinventory.RawGCP
	if err := json.Unmarshal([]byte(js), &r); err != nil {
		t.Fatal(err)
	}
	return r
}

// An unconditioned GitHub pool plus a pool-wide impersonation binding: gcpwif's critical join.
const openWIFProject = `{"project_id":"proj-1","wif_providers":[{
  "project_number":"1234567890","pool_id":"ci-pool","id":"github",
  "issuer_uri":"https://token.actions.githubusercontent.com"}],
  "service_accounts":[{"email":"deploy@proj-1.iam.gserviceaccount.com","admin":true,"bindings":[{
    "role":"roles/iam.serviceAccountTokenCreator",
    "members":["principalSet://iam.googleapis.com/projects/1234567890/locations/global/workloadIdentityPools/ci-pool/*"]}]}],
  "buckets":[{"name":"pub","public":true}]}`

func gcpTenant(t *testing.T, projects ...string) (*store.Memory, *cloudsnap.MemStore) {
	t.Helper()
	ctx := context.Background()
	st := store.NewMemory()
	_ = st.PutTenant(ctx, platform.Tenant{ID: "ten-1"})
	for _, p := range projects {
		_ = st.PutConnection(ctx, platform.Connection{ID: "c-" + p, TenantID: "ten-1", Kind: platform.ConnGCP,
			Account: p, SecretRef: p, Status: platform.ConnActive, CreatedAt: time.Now()})
	}
	return st, cloudsnap.NewMemStore()
}

// A connected project is READ, stored under its own account, and run through the same assessments the
// posted door runs — the CI-identity join and the coverage notes — with what the read could not see
// stored beside them.
func TestSyncGCPInventory_ReadsStoresAndAssessesLikeThePostedDoor(t *testing.T) {
	ctx := context.Background()
	st, snaps := gcpTenant(t, "proj-1")
	d := Deps{Store: st, CloudSnapshots: snaps, GCPFetcher: func(platform.Connection) GCPFetcher {
		return fakeGCPFetcher{res: gcpfetch.Result{
			Raw: rawGCP(t, openWIFProject), Sources: []string{"iam-policy", "service-accounts"},
			Skipped: map[string]string{"compute": "compute.instances.list denied"},
		}}
	}}

	if _, _, err := d.SyncGCPInventory(ctx, "ten-1"); err != nil {
		t.Fatalf("sync: %v", err)
	}
	snap, ok, _ := snaps.GetAccount(ctx, "ten-1", "gcp:proj-1")
	if !ok || !strings.Contains(string(snap.Inventory), "deploy@proj-1") {
		t.Fatalf("project not stored under its own account: ok=%v %s", ok, snap.Inventory)
	}
	if _, ok := snap.CoverageGaps["not-read: compute"]; !ok {
		t.Errorf("an unread surface must be stored as a coverage gap, got %v", snap.CoverageGaps)
	}
	fs, _ := st.ListFindings(ctx, "ten-1", store.FindingFilter{})
	var ci bool
	for _, f := range fs {
		if strings.Contains(f.Title+f.Description, "deploy@proj-1.iam.gserviceaccount.com") {
			ci = true
		}
	}
	if !ci {
		t.Errorf("the live door skipped the CI-identity assessment the posted door runs (%d findings)", len(fs))
	}
}

// A failed read is a failure: nothing stored, the error named — and the OTHER project still applies.
func TestSyncGCPInventory_OneProjectFailingDoesNotHideTheOther(t *testing.T) {
	ctx := context.Background()
	st, snaps := gcpTenant(t, "proj-1", "proj-2")
	d := Deps{Store: st, CloudSnapshots: snaps, GCPFetcher: func(c platform.Connection) GCPFetcher {
		if c.Account == "proj-2" {
			return fakeGCPFetcher{err: errors.New("the project IAM policy could not be read")}
		}
		return fakeGCPFetcher{res: gcpfetch.Result{Raw: rawGCP(t, openWIFProject)}}
	}}
	_, results, err := d.SyncGCPInventory(ctx, "ten-1")
	if err == nil || !strings.Contains(err.Error(), "proj-2") {
		t.Fatalf("a failed project must be reported by name, got %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("want a result per project, got %d", len(results))
	}
	if _, ok, _ := snaps.GetAccount(ctx, "ten-1", "gcp:proj-1"); !ok {
		t.Error("the project that read fine was not stored")
	}
	if _, ok, _ := snaps.GetAccount(ctx, "ten-1", "gcp:proj-2"); ok {
		t.Error("a project whose read failed was stored")
	}
}

// An empty read is refused, as the posted door refuses it: stored, it would become the drift baseline
// and the next real read would report every resource as newly created.
func TestSyncGCPInventory_EmptyReadIsNotStored(t *testing.T) {
	ctx := context.Background()
	st, snaps := gcpTenant(t, "proj-1")
	d := Deps{Store: st, CloudSnapshots: snaps, GCPFetcher: func(platform.Connection) GCPFetcher {
		return fakeGCPFetcher{res: gcpfetch.Result{Raw: gcpinventory.RawGCP{ProjectID: "proj-1"}}}
	}}
	if _, _, err := d.SyncGCPInventory(ctx, "ten-1"); err == nil {
		t.Fatal("an empty project read must fail, not succeed quietly")
	}
	if _, ok, _ := snaps.GetAccount(ctx, "ten-1", "gcp:proj-1"); ok {
		t.Error("an empty read was stored as the baseline")
	}
}

// No GCP connection and no fetcher are "unavailable", not failures — the scheduled pass stays quiet.
func TestSyncClouds_NothingConnectedIsUnavailable(t *testing.T) {
	st, snaps := gcpTenant(t)
	d := Deps{Store: st, CloudSnapshots: snaps, GCPFetcher: func(platform.Connection) GCPFetcher { return fakeGCPFetcher{} }}
	if _, err := d.SyncClouds(context.Background(), "ten-1"); !errors.Is(err, ErrCloudSyncUnavailable) {
		t.Fatalf("want ErrCloudSyncUnavailable, got %v", err)
	}
}

// A GCP project that reads cleanly is a cloud that RAN: the scheduled pass must not report the whole
// cloud surface as unavailable just because AWS is not connected.
func TestSyncClouds_GCPAloneCounts(t *testing.T) {
	st, snaps := gcpTenant(t, "proj-1")
	d := Deps{Store: st, CloudSnapshots: snaps, GCPFetcher: func(platform.Connection) GCPFetcher {
		return fakeGCPFetcher{res: gcpfetch.Result{Raw: rawGCP(t, openWIFProject)}}
	}}
	if _, err := d.SyncClouds(context.Background(), "ten-1"); err != nil {
		t.Fatalf("a GCP-only tenant whose project read fine reported %v", err)
	}
}

func TestHandleCloudSync_GCP(t *testing.T) {
	st, snaps := gcpTenant(t, "proj-1")
	call := func(d Deps) (int, map[string]any) {
		rec := httptest.NewRecorder()
		d.handleCloudSync(rec, httptest.NewRequest(http.MethodPost, "/v1/cloud/sync?provider=gcp", nil), "ten-1")
		var body map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &body)
		return rec.Code, body
	}
	if code, body := call(Deps{Store: st, CloudSnapshots: snaps}); code != http.StatusServiceUnavailable || body["reason"] != "live_fetch_unavailable" {
		t.Errorf("no fetcher: got %d %v", code, body)
	}
	d := Deps{Store: st, CloudSnapshots: snaps, GCPFetcher: func(platform.Connection) GCPFetcher {
		return fakeGCPFetcher{err: errors.New("denied")}
	}}
	if code, body := call(d); code != http.StatusBadGateway || body["failed"] != float64(1) {
		t.Errorf("all projects failing must be a 502, got %d %v", code, body)
	}
	d.GCPFetcher = func(platform.Connection) GCPFetcher {
		return fakeGCPFetcher{res: gcpfetch.Result{Raw: rawGCP(t, openWIFProject), Sources: []string{"iam-policy"}}}
	}
	code, body := call(d)
	ps, _ := body["projects"].([]any)
	if code != http.StatusOK || len(ps) != 1 {
		t.Fatalf("got %d %v", code, body)
	}
	if p := ps[0].(map[string]any); p["project"] != "proj-1" || p["coverage"] == nil {
		t.Errorf("each project must report what it covered: %v", p)
	}
}
