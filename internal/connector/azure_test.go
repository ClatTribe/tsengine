package connector

import (
	"context"
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/pkg/platform"
)

const goodSub = "12345678-1234-1234-1234-123456789abc"

func TestAzure_KindAndOAuthURL(t *testing.T) {
	a := NewAzure("app-guid-123")
	if a.Kind() != platform.ConnAzure {
		t.Errorf("kind = %q", a.Kind())
	}
	u := a.OAuthURL("tenant-123", "")
	for _, want := range []string{"SubscriptionsBlade", "state=tenant-123", "Reader", "app-guid-123"} {
		if !strings.Contains(u, want) {
			t.Errorf("oauth url missing %q: %s", want, u)
		}
	}
}

func TestAzure_ExchangeRecordsSubscription(t *testing.T) {
	a := NewAzure("app")
	conn, err := a.Exchange(context.Background(), "  "+goodSub+"  ", "")
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if conn.Kind != platform.ConnAzure || conn.Account != goodSub || conn.SecretRef != goodSub || conn.Status != platform.ConnActive {
		t.Errorf("connection wrong: %+v", conn)
	}
}

func TestAzure_ExchangeRejectsBadSubscriptionID(t *testing.T) {
	a := NewAzure("app")
	for _, bad := range []string{
		"not-a-guid",
		"12345678-1234-1234-1234-123456789ab",  // 11 in last group
		"1234567-1234-1234-1234-123456789abc",  // 7 in first group
		"12345678-1234-1234-1234-123456789abg", // non-hex 'g'
		"",
	} {
		if _, err := a.Exchange(context.Background(), bad, ""); err == nil {
			t.Errorf("subscription id %q should be rejected", bad)
		}
	}
	if _, err := a.Exchange(context.Background(), strings.ToUpper(goodSub), ""); err != nil {
		t.Errorf("an uppercase GUID should be accepted (normalized): %v", err)
	}
}

func TestAzure_DiscoverYieldsCloudAccount(t *testing.T) {
	a := NewAzure("app")
	assets, err := a.Discover(context.Background(), platform.Connection{ID: "c1", TenantID: "t1", Account: goodSub}, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(assets) != 1 {
		t.Fatalf("want 1 asset, got %d", len(assets))
	}
	got := assets[0]
	if got.Type != "cloud_account" || got.Target != goodSub || got.ConnectionID != "c1" {
		t.Errorf("asset wrong: %+v", got)
	}
	if got.Meta["provider"] != "azure" || got.Meta["subscription_id"] != goodSub {
		t.Errorf("asset meta wrong: %+v", got.Meta)
	}
}

type fakeAzureWriter struct {
	sub, rg, account string
}

func (f *fakeAzureWriter) DisableStoragePublicAccess(_ context.Context, sub, rg, account string) error {
	f.sub, f.rg, f.account = sub, rg, account
	return nil
}

func TestAzure_ApplyDisablesStoragePublicAccess(t *testing.T) {
	w := &fakeAzureWriter{}
	a := NewAzure("app")
	a.Writer = w
	// target as a full ARM resource ID
	rid := "/subscriptions/" + goodSub + "/resourceGroups/rg-prod/providers/Microsoft.Storage/storageAccounts/acmestg"
	act := platform.Action{Kind: platform.ActApplyConfig, Payload: map[string]any{
		"remediation_type": "azure_storage_disable_public_access", "target": rid,
	}}
	if err := a.Apply(context.Background(), platform.Connection{Account: goodSub}, "", act); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if w.sub != goodSub || w.rg != "rg-prod" || w.account != "acmestg" {
		t.Errorf("writer called with sub=%q rg=%q account=%q", w.sub, w.rg, w.account)
	}
	// the compact "rg/account" target form also resolves
	if rg, acct := azureStorageTarget("rg-x/acct-y"); rg != "rg-x" || acct != "acct-y" {
		t.Errorf("compact target parse wrong: rg=%q acct=%q", rg, acct)
	}
}

func TestAzure_WatchNoopAndApplyStub(t *testing.T) {
	a := NewAzure("app")
	if trigs, _ := a.Watch(context.Background(), platform.Connection{}, []byte(`{}`)); len(trigs) != 0 {
		t.Errorf("cloud Watch should be a no-op, got %+v", trigs)
	}
	if err := a.Apply(context.Background(), platform.Connection{}, "", platform.Action{ID: "a1"}); err == nil {
		t.Error("Apply with no remediation_type must error")
	}
	err := a.Apply(context.Background(), platform.Connection{}, "", platform.Action{ID: "a2", Payload: map[string]any{"remediation_type": "nsg_lock"}})
	if err == nil || !strings.Contains(err.Error(), "no live Azure write path") {
		t.Errorf("Apply should surface the no-live-write-path stub, got %v", err)
	}
}
