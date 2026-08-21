package platformapi

import (
	"context"
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/internal/cloudsnap"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

// The reader of the attack-path page is rarely the CI job that posted the inventory. This
// asserts the caveat survives the gap between them.
func TestDegradation_StoredCoverageGapReachesTheReader(t *testing.T) {
	ctx := context.Background()
	d, st := stateDeps(t)
	_ = st.PutTenant(ctx, platform.Tenant{ID: "t", Name: "A"})
	snaps := cloudsnap.NewMemStore()
	_ = snaps.Put(ctx, cloudsnap.Snapshot{
		TenantID: "t", Inventory: []byte(`{"account_id":"1"}`),
		CoverageGaps: map[string]string{
			"privilege-escalation": "no policy documents in the snapshot — populate `policies`.",
		},
	})
	d.CloudSnapshots = snaps

	var got *Degradation
	for _, g := range d.computeDegradations(ctx, "t") {
		if g.Kind == DegradationCloudCoverage {
			gg := g
			got = &gg
		}
	}
	if got == nil {
		t.Fatal("a stored coverage gap must surface — otherwise zero escalation paths reads as 'nobody can become admin'")
	}
	if !strings.Contains(got.Detail, "could not look") {
		t.Fatalf("the detail must say we could not look, not that nothing is there: %q", got.Detail)
	}
	if !strings.Contains(got.Detail, "policies") {
		t.Fatalf("the reason must carry the field to populate: %q", got.Detail)
	}
}

// A COMPLETE snapshot must produce nothing. A permanent warning is ignored exactly as
// reliably as a missing one, which is the failure this whole file guards against.
func TestDegradation_CompleteSnapshotIsSilent(t *testing.T) {
	ctx := context.Background()
	d, st := stateDeps(t)
	_ = st.PutTenant(ctx, platform.Tenant{ID: "t", Name: "A"})
	snaps := cloudsnap.NewMemStore()
	_ = snaps.Put(ctx, cloudsnap.Snapshot{TenantID: "t", Inventory: []byte(`{"account_id":"1"}`)})
	d.CloudSnapshots = snaps

	for _, g := range d.computeDegradations(ctx, "t") {
		if g.Kind == DegradationCloudCoverage {
			t.Fatal("a snapshot with no recorded gaps must not warn")
		}
	}
}

// NO snapshot at all is not a coverage gap. "We have never been given a cloud inventory"
// and "the inventory we have is partial" are different claims, and inferring the second
// from the first is the cry-wolf failure this file's header warns about.
func TestDegradation_NoSnapshotIsNotACoverageGap(t *testing.T) {
	ctx := context.Background()
	d, st := stateDeps(t)
	_ = st.PutTenant(ctx, platform.Tenant{ID: "t", Name: "A"})
	d.CloudSnapshots = cloudsnap.NewMemStore()

	for _, g := range d.computeDegradations(ctx, "t") {
		if g.Kind == DegradationCloudCoverage {
			t.Fatal("no snapshot is not a partial snapshot — do not infer one from the other")
		}
	}
}
