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
	"github.com/ClatTribe/tsengine/internal/connector/awsfetch"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

// Through the posted-inventory DOOR, not the join function: the tenant's own web hostname must reach
// the stored snapshot on the instance it resolves to, and the response must say what could not be
// joined — a load balancer or CDN in front is the common case and reads as "no link" otherwise.
func TestIngestAWSInventory_JoinsTheTenantsHostnamesToInstances(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	_ = st.PutTenant(ctx, platform.Tenant{ID: "t1"})
	_ = st.PutAsset(ctx, platform.Asset{ID: "w", TenantID: "t1", Type: "web_application", Target: "https://app.acme.com/login"})
	_ = st.PutAsset(ctx, platform.Asset{ID: "c", TenantID: "t1", Type: "web_application", Target: "https://www.acme.com"})
	snaps := cloudsnap.NewMemStore()
	d := Deps{Store: st, CloudSnapshots: snaps, LookupHost: func(_ context.Context, h string) ([]string, error) {
		return map[string][]string{"app.acme.com": {"3.3.3.3"}, "www.acme.com": {"104.16.0.1"}}[h], nil
	}}
	body := `{"account_id":"111122223333","instances":[{"id":"i-web","public_ip":true,"public_ip_address":"3.3.3.3",
		"security_group_ids":["sg-1"],"service_port":443}],"security_groups":[{"id":"sg-1"}]}`
	rec := httptest.NewRecorder()
	d.handleIngestAWSInventory(rec, httptest.NewRequest(http.MethodPost, "/v1/cloud/inventory", strings.NewReader(body)), "t1")
	if rec.Code != http.StatusOK {
		t.Fatalf("ingest: %d %s", rec.Code, rec.Body)
	}
	snap, ok, _ := snaps.Get(ctx, "t1")
	inv, err := cloudgraph.ParseInventory(snap.Inventory)
	if !ok || err != nil {
		t.Fatalf("no stored inventory: %v", err)
	}
	found := false
	for _, r := range inv.Resources {
		if r.ID == "i-web" || strings.HasSuffix(r.ID, "i-web") {
			for _, n := range r.DNSNames {
				found = found || n == "app.acme.com"
			}
		}
	}
	if !found {
		t.Fatal("the hostname that resolves to the instance must be recorded on it in the stored inventory")
	}
	var resp map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	hj, _ := resp["hostname_join"].(map[string]any)
	note, _ := hj["note"].(string)
	if !strings.Contains(note, "1 of your 2") || !strings.Contains(note, "resolve somewhere else") {
		t.Fatalf("the response must say what was joined and what resolves elsewhere: %q (%v)", note, resp)
	}
	// A CDN in front is architecture, not a gap: it must never surface as unread coverage.
	if gaps, _ := resp["coverage_gaps"].(map[string]any); gaps["hostnames"] != nil {
		t.Fatal("an unjoinable hostname must not be reported as a coverage gap — that feeds a banner the customer cannot clear")
	}
}

type fetchCompute struct{ ins []awsfetch.Instance }

func (f fetchCompute) ListCompute(context.Context) ([]awsfetch.Instance, []awsfetch.SecurityGroup, error) {
	return f.ins, []awsfetch.SecurityGroup{{ID: "sg-1"}}, nil
}

// The SCHEDULED live sync is the door a connected customer actually uses; it must make the same join.
func TestCloudSync_LivePathJoinsTheTenantsHostnames(t *testing.T) {
	d := syncDeps(t, fetchLister{out: []awsfetch.Bucket{{Name: "logs"}}}, true)
	_ = d.Store.PutAsset(context.Background(), platform.Asset{ID: "w", TenantID: "ten-1", Type: "web_application", Target: "https://app.acme.com"})
	d.LookupHost = func(_ context.Context, h string) ([]string, error) { return []string{"3.3.3.3"}, nil }
	d.AWSFetcher = func(c platform.Connection) awsfetch.Fetcher {
		return awsfetch.Fetcher{AccountID: c.Account, Buckets: fetchLister{out: []awsfetch.Bucket{{Name: "logs"}}},
			Compute: fetchCompute{ins: []awsfetch.Instance{{ID: "i-web", PublicIP: true, PublicIPAddress: "3.3.3.3",
				PublicDNSName: "ec2-3-3-3-3.compute.amazonaws.com", SGIDs: []string{"sg-1"}}}}}
	}
	if _, _, err := d.SyncCloudInventory(context.Background(), "ten-1"); err != nil {
		t.Fatalf("sync: %v", err)
	}
	snap, _, _ := d.CloudSnapshots.Get(context.Background(), "ten-1")
	inv, err := cloudgraph.ParseInventory(snap.Inventory)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, r := range inv.Resources {
		names = append(names, r.DNSNames...)
	}
	joined := strings.Join(names, ",")
	if !strings.Contains(joined, "app.acme.com") || !strings.Contains(joined, "ec2-3-3-3-3.compute.amazonaws.com") {
		t.Fatalf("the live read must carry both AWS's own DNS name and the tenant hostname that resolves to it: %v", names)
	}
}
