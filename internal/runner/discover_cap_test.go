package runner

import (
	"context"
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/internal/connector"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

// threeRepoConn discovers three repositories — one more than the Free plan allows.
type threeRepoConn struct{ fakeConn }

func (threeRepoConn) Discover(_ context.Context, c platform.Connection, _ string) ([]platform.Asset, error) {
	return []platform.Asset{
		{TenantID: c.TenantID, ConnectionID: c.ID, Type: "repository", Target: "https://github.com/acme/web"},
		{TenantID: c.TenantID, ConnectionID: c.ID, Type: "repository", Target: "https://github.com/acme/api"},
		{TenantID: c.TenantID, ConnectionID: c.ID, Type: "repository", Target: "https://github.com/acme/infra"},
	}, nil
}

func capService(plan string) (*Service, *fakeScanner, store.Store) {
	st := store.NewMemory()
	sc := &fakeScanner{}
	n := 0
	_ = st.PutTenant(context.Background(), platform.Tenant{ID: "t1", Plan: plan})
	return &Service{Store: st, Connectors: connector.NewRegistry(threeRepoConn{}), Tokens: fakeTokens{}, Scanner: sc, NewID: func() string { n++; return itoa(n) }}, sc, st
}

// POST /v1/assets refused an over-cap add with a 402, but Discover registered every repository in
// the org regardless — so on Free the cap was theatre for the path most tenants take. The cap must
// hold on discovery AND name what it left out; a silent cap leaves the customer believing the whole
// org is scanned when only the first two repositories are.
func TestDiscoverAndScan_HonoursPlanAssetCapAndNamesTheSkipped(t *testing.T) {
	svc, sc, st := capService(platform.PlanFree) // MaxAssets: 2
	ctx := context.Background()
	scanned, err := svc.DiscoverAndScan(ctx, platform.Connection{ID: "c1", TenantID: "t1", Kind: platform.ConnGitHub})
	if scanned != 2 || sc.calls != 2 {
		t.Fatalf("Free allows 2 assets: want 2 scanned, got scanned=%d calls=%d", scanned, sc.calls)
	}
	if err == nil || !strings.Contains(err.Error(), "acme/infra") || !strings.Contains(err.Error(), "up to 2") {
		t.Fatalf("the cap must be reported and NAME the skipped asset, got %v", err)
	}
	if assets, _ := st.ListAssets(ctx, "t1"); len(assets) != 2 {
		t.Fatalf("want exactly 2 registered, got %d", len(assets))
	}
	// A second discovery of the SAME repositories must not report the already-registered ones as
	// newly skipped, and must not register duplicates.
	scanned, err = svc.DiscoverAndScan(ctx, platform.Connection{ID: "c1", TenantID: "t1", Kind: platform.ConnGitHub})
	if scanned != 2 || err == nil || !strings.Contains(err.Error(), "1 discovered asset was not registered") {
		t.Fatalf("re-discovery: want the 2 known assets rescanned and only infra skipped, got scanned=%d err=%v", scanned, err)
	}
	// ...and the store must still hold exactly 2 assets. Re-discovery used to MINT A FRESH ID for each
	// already-known repo (Discover returns none), registering a duplicate record per repo per pass —
	// findings then stamped one duplicate while a product referenced another, so the product-scoped
	// VAPT read a false "Clear". Asserting the count is what catches it; the scanned+error checks above
	// passed even while duplicates piled up.
	if a, _ := st.ListAssets(ctx, "t1"); len(a) != 2 {
		t.Fatalf("re-discovery must not register duplicates: want 2 assets, got %d", len(a))
	}
}

// Two connections discovering the SAME org — the common case behind a false product-scoped "Clear":
// an org connected twice (a reconnect, a second install) doubled every asset, so one repository
// became several records with different ids. The fix converges on one asset per (type, target)
// regardless of which connection or how many passes discovered it.
func TestDiscoverAndScan_ReDiscoveryDoesNotDuplicateAssets(t *testing.T) {
	svc, _, st := capService(platform.PlanEnterprise) // unlimited — the cap is not what dedups
	ctx := context.Background()
	for _, conn := range []string{"connA", "connB", "connA"} {
		if _, err := svc.DiscoverAndScan(ctx, platform.Connection{ID: conn, TenantID: "t1", Kind: platform.ConnGitHub}); err != nil {
			t.Fatalf("discover via %s: %v", conn, err)
		}
	}
	if a, _ := st.ListAssets(ctx, "t1"); len(a) != 3 {
		t.Fatalf("three repos discovered thrice across two connections must leave 3 assets, got %d", len(a))
	}
}

// Enterprise (-1) is unlimited; a tenant with no record is left alone (the cap never invents a plan).
func TestDiscoverAndScan_NoCapForUnlimitedOrUnknownTenant(t *testing.T) {
	svc, sc, _ := capService(platform.PlanEnterprise)
	if n, err := svc.DiscoverAndScan(context.Background(), platform.Connection{ID: "c1", TenantID: "t1", Kind: platform.ConnGitHub}); n != 3 || err != nil || sc.calls != 3 {
		t.Fatalf("enterprise: want all 3 scanned, got n=%d err=%v", n, err)
	}
	svc, sc, _ = capService(platform.PlanFree)
	if n, err := svc.DiscoverAndScan(context.Background(), platform.Connection{ID: "c1", TenantID: "nobody", Kind: platform.ConnGitHub}); n != 3 || err != nil || sc.calls != 3 {
		t.Fatalf("unknown tenant: the cap must not apply a plan it cannot read, got n=%d err=%v", n, err)
	}
}
