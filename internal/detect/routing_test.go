package detect

import (
	"context"
	"testing"

	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// An incident opened from a finding on an owned asset names the owner, and @mentions them when their
// Slack member id is on the escalation roster; an unowned asset is said to be unowned; a finding with no
// asset says nothing about ownership. Three states, three different fixes for the reader.
func TestReconcile_IncidentCarriesTheAssetOwner(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	_ = st.PutTenant(ctx, platform.Tenant{ID: "t1", Contacts: []platform.Contact{
		{ID: "c1", Name: "Priya", Email: "priya@acme.com", SlackID: "U012ABCDEF"}, // emails match case-insensitively
	}})
	_ = st.PutAsset(ctx, platform.Asset{ID: "a-owned", TenantID: "t1", Target: "https://app.acme.com", Owner: "Priya@ACME.com", Team: "payments"})
	_ = st.PutAsset(ctx, platform.Asset{ID: "a-unowned", TenantID: "t1", Target: "https://old.acme.com"})

	owned := crit("nuclei::sqli", "https://app.acme.com/q")
	owned.AssetID = "a-owned"
	unowned := crit("nuclei::xss", "https://old.acme.com/s")
	unowned.AssetID = "a-unowned"
	loose := crit("osint::leak", "somewhere")
	gone := crit("nuclei::rce", "https://gone.acme.com")
	gone.AssetID = "a-deleted" // the asset no longer exists: unknown, not unowned

	if _, err := newDetector(st).Reconcile(ctx, "t1", []types.Finding{owned, unowned, loose, gone}, nil); err != nil {
		t.Fatal(err)
	}
	by := map[string]platform.Incident{}
	for _, i := range openIncidents(t, st, "t1") {
		by[i.RuleID] = i
	}
	if i := by["nuclei::sqli"]; i.Owner != "Priya@ACME.com" || i.Team != "payments" || i.OwnerSlackID != "U012ABCDEF" || i.AssetID != "a-owned" {
		t.Errorf("owned asset: %+v", i)
	}
	if i := by["nuclei::xss"]; i.AssetID != "a-unowned" || i.Owner != "" || i.AssetTarget != "https://old.acme.com" {
		t.Errorf("an unowned asset must be recorded as known-but-unowned: %+v", i)
	}
	if i := by["nuclei::rce"]; i.AssetID != "" {
		t.Errorf("a finding naming an asset that no longer exists must not be rendered as unowned: %+v", i)
	}
	if i := by["osint::leak"]; i.AssetID != "" || i.Owner != "" {
		t.Errorf("a finding with no asset must say nothing about ownership: %+v", i)
	}
}

// Detect's narrow Store still works: a store that cannot read assets opens incidents unrouted.
type narrowStore struct{ *store.Memory }

func (n narrowStore) PutIncident(ctx context.Context, i platform.Incident) error {
	return n.Memory.PutIncident(ctx, i)
}
func (n narrowStore) ListIncidents(ctx context.Context, t string) ([]platform.Incident, error) {
	return n.Memory.ListIncidents(ctx, t)
}

func TestReconcile_NarrowStoreOpensUnrouted(t *testing.T) {
	ctx := context.Background()
	mem := store.NewMemory()
	f := crit("nuclei::sqli", "x")
	f.AssetID = "a1"
	d := newDetector(struct {
		Store
	}{narrowStore{mem}})
	res, err := d.Reconcile(ctx, "t1", []types.Finding{f}, nil)
	if err != nil || len(res.Opened) != 1 || res.Opened[0].AssetID != "" {
		t.Fatalf("res=%+v err=%v", res, err)
	}
}
