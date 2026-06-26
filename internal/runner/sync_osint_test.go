package runner

import (
	"context"
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// syncOSINT makes external exposure a continuously-monitored surface: each pass it runs the keyless CT
// collector over the tenant's domain assets and a host that newly appears in CT becomes a finding (which
// the Detector then turns into an incident). Hermetic — a fake fetcher returns a crt.sh response.
func TestSyncOSINT_DiscoversNewExposedHostFromCT(t *testing.T) {
	st := store.NewMemory()
	ctx := context.Background()
	_ = st.PutTenant(ctx, platform.Tenant{ID: "t1", Name: "Acme"})
	_ = st.PutAsset(ctx, platform.Asset{ID: "a1", TenantID: "t1", Type: string(types.AssetDomain), Target: "acme.com"})

	n := 0
	svc := &Service{
		Store: st,
		NewID: func() string { n++; return itoa(n) },
		// fake CT fetcher: crt.sh JSON surfacing a forgotten subdomain in the org's own subtree
		OSINTFetcher: func(_ context.Context, _ string) ([]byte, error) {
			return []byte(`[{"name_value":"staging.acme.com"},{"name_value":"*.acme.com"}]`), nil
		},
	}

	out := svc.syncOSINT(ctx, "t1")
	var host *types.Finding
	for i := range out {
		if out[i].RuleID == "osint::exposed-host" && strings.Contains(out[i].Endpoint, "staging.acme.com") {
			host = &out[i]
		}
	}
	if host == nil {
		t.Fatalf("syncOSINT should surface the newly-discovered staging.acme.com host, got %+v", out)
	}
	// Persisted, so it appears in Issues/OSINT like any finding.
	stored, _ := st.ListFindings(ctx, "t1", store.FindingFilter{})
	if len(stored) == 0 {
		t.Errorf("the OSINT finding should be persisted")
	}
}

// No domain assets → no OSINT (never a false finding); no fetcher → no-op.
func TestSyncOSINT_NoDomainsOrFetcherIsNoop(t *testing.T) {
	st := store.NewMemory()
	ctx := context.Background()
	_ = st.PutTenant(ctx, platform.Tenant{ID: "t1", Name: "Acme"})
	// has a fetcher but no domain asset
	svc := &Service{Store: st, NewID: func() string { return "x" },
		OSINTFetcher: func(_ context.Context, _ string) ([]byte, error) { return []byte(`[]`), nil }}
	if out := svc.syncOSINT(ctx, "t1"); out != nil {
		t.Errorf("no domain assets → nil, got %+v", out)
	}
	// has a domain but no fetcher
	_ = st.PutAsset(ctx, platform.Asset{ID: "a1", TenantID: "t1", Type: string(types.AssetDomain), Target: "acme.com"})
	svc2 := &Service{Store: st, NewID: func() string { return "x" }}
	if out := svc2.syncOSINT(ctx, "t1"); out != nil {
		t.Errorf("no fetcher → nil, got %+v", out)
	}
}
