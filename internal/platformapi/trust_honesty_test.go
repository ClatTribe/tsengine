package platformapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

// The Trust Center is the highest-stakes surface in the product: the reader is a PROSPECT doing
// vendor due diligence on a company that trusted us to describe them accurately. A claim we cannot
// back here is not an internal inaccuracy, it is a misrepresentation made to a third party.
//
// Found by running the product: a workspace with one unscanned asset and zero engagements published
// "Continuously monitored · Re-scanned on every change". Monitored and Signed were hardcoded true.

func trustDeps(t *testing.T) (Deps, string) {
	t.Helper()
	st := store.NewMemory()
	ctx := context.Background()
	if err := st.PutTenant(ctx, platform.Tenant{ID: "t1", Name: "Acme"}); err != nil {
		t.Fatal(err)
	}
	return Deps{Store: st, Token: "test-token"}, "t1"
}

func fetchTrust(t *testing.T, d Deps, tenant string) trustView {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet,
		"/v1/trust/"+tenant+"?token="+d.trustToken(tenant), nil)
	req.SetPathValue("tenant", tenant)
	w := httptest.NewRecorder()
	d.handleTrust(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("trust page returned %d", w.Code)
	}
	var v trustView
	if err := json.Unmarshal(w.Body.Bytes(), &v); err != nil {
		t.Fatal(err)
	}
	return v
}

// A workspace that has never been scanned must NOT tell its customers it is continuously monitored.
func TestTrust_NeverScannedIsNotMonitored(t *testing.T) {
	d, tenant := trustDeps(t)
	// An asset exists but nothing has ever run against it — the state every new customer is in.
	_ = d.Store.PutAsset(context.Background(), platform.Asset{
		ID: "a1", TenantID: tenant, Type: "domain", Target: "acme.io"})

	if v := fetchTrust(t, d, tenant); v.Monitored {
		t.Fatal("a workspace with zero completed scans published \"continuously monitored\" to its " +
			"own prospects — a claim about a customer, made to a third party, that nothing backs")
	}
}

// And once a scan HAS completed, the claim becomes true — the guard must not be unsatisfiable.
func TestTrust_CompletedScanIsMonitored(t *testing.T) {
	d, tenant := trustDeps(t)
	ctx := context.Background()
	_ = d.Store.PutAsset(ctx, platform.Asset{ID: "a1", TenantID: tenant, Type: "domain", Target: "acme.io"})
	_ = d.Store.PutEngagement(ctx, platform.Engagement{
		ID: "e1", TenantID: tenant, AssetID: "a1", CompletedAt: time.Now()})

	if v := fetchTrust(t, d, tenant); !v.Monitored {
		t.Fatal("a workspace with a completed scan is not reported as monitored")
	}
}

// An engagement that is still RUNNING is not a completed scan.
func TestTrust_RunningScanIsNotYetMonitored(t *testing.T) {
	d, tenant := trustDeps(t)
	ctx := context.Background()
	_ = d.Store.PutAsset(ctx, platform.Asset{ID: "a1", TenantID: tenant, Type: "domain", Target: "acme.io"})
	_ = d.Store.PutEngagement(ctx, platform.Engagement{ID: "e1", TenantID: tenant, AssetID: "a1"})

	if v := fetchTrust(t, d, tenant); v.Monitored {
		t.Error("an in-flight scan counted as continuous monitoring")
	}
}

// "Evidence signed" means THIS workspace has a signed decision trail, not that the platform is
// capable of signing. An empty workspace has no evidence to sign.
func TestTrust_NoDecisionsMeansNoSignedEvidence(t *testing.T) {
	d, tenant := trustDeps(t)
	if v := fetchTrust(t, d, tenant); v.Signed {
		t.Fatal("an empty workspace claimed signed evidence to its customers")
	}
}

func TestTrust_DecisionsMeanSignedEvidence(t *testing.T) {
	d, tenant := trustDeps(t)
	_ = d.Store.PutAction(context.Background(), platform.Action{
		ID: "act1", TenantID: tenant, Kind: platform.ActFileTicket, Status: platform.ActApplied})

	if v := fetchTrust(t, d, tenant); !v.Signed {
		t.Error("a workspace with a recorded decision is not reported as having signed evidence")
	}
}

// The org name and coverage still render — withholding an unbacked badge must not blank the page.
func TestTrust_StillRendersWithoutTheBadges(t *testing.T) {
	d, tenant := trustDeps(t)
	v := fetchTrust(t, d, tenant)
	if v.Org != "Acme" {
		t.Errorf("org = %q", v.Org)
	}
	if v.Frameworks == nil {
		t.Error("frameworks serialized as null — the public page's .map would crash")
	}
}
