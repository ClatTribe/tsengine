package connector

import (
	"context"
	"testing"

	"github.com/ClatTribe/tsengine/internal/tool/prowler"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

// THE BUG THIS CLOSES. A cloud connector's Discover sets the cloud_account asset's Target, and the
// cloud Handler feeds that Target straight to prowler/scoutsuite as the PROVIDER. Discover used to
// set Target = nz(c.Account, provider), so a connection with an account id — every onboarded one —
// produced Target = "123456789012", which prowler rejects as "unsupported provider". The whole
// scan pipeline worked and then failed at the tool call, for every cloud account.
//
// The guard asserts Target against prowler's OWN exported provider set, so it cannot drift from what
// the tool actually accepts, AND that the account id is not lost (it moves to Meta).
func TestCloudDiscover_TargetIsAProviderProwlerAccepts(t *testing.T) {
	const account = "123456789012" // a populated account id — the case that used to break
	cases := []struct {
		name string
		disc interface {
			Discover(context.Context, platform.Connection, string) ([]platform.Asset, error)
		}
	}{
		{"aws", &AWS{}},
		{"gcp", &GCP{}},
		{"azure", &Azure{}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assets, err := c.disc.Discover(context.Background(),
				platform.Connection{TenantID: "t1", ID: "conn1", Account: account}, "")
			if err != nil {
				t.Fatalf("Discover: %v", err)
			}
			if len(assets) != 1 {
				t.Fatalf("want 1 cloud_account asset, got %d", len(assets))
			}
			a := assets[0]
			if !prowler.Accepts(a.Target) {
				t.Errorf("Target %q is not a provider prowler accepts — the scan will fail with "+
					"'unsupported provider'", a.Target)
			}
			// The account id must survive somewhere, or a real datum is silently dropped.
			found := false
			for _, v := range a.Meta {
				if v == account {
					found = true
				}
			}
			if !found {
				t.Errorf("the account id %q was not preserved in Meta: %v", account, a.Meta)
			}
		})
	}
}
