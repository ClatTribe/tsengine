package platformapi

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/ClatTribe/tsengine/internal/connector"
	"github.com/ClatTribe/tsengine/internal/grc"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// A buyer reviewing one product is handed the penetration test report FOR that product — its assets only,
// with who confirmed the scope — not the whole workspace's list of open holes. And when the product it was
// pinned to is gone, the report is withheld rather than quietly served for everything.
func TestTrustCenter_ProductScopedPentestReport(t *testing.T) {
	trustRequestLimiter.reset()
	ctx := context.Background()
	st := store.NewMemory()
	d := Deps{Store: st, Connectors: connector.NewRegistry(), Token: "platform-tok", GRC: &grc.GRC{Store: st}}
	h := NewHandler(d)

	now := time.Now().UTC()
	_ = st.PutTenant(ctx, platform.Tenant{ID: "t1", Name: "Acme",
		Products: []platform.Product{{ID: "p-checkout", Name: "Checkout", AssetIDs: []string{"a-pay"}, ConfirmedBy: "cto@acme.com", ConfirmedAt: now}},
		TrustCenter: &platform.TrustCenterConfig{Enabled: true, AutoApproveDomains: []string{"buyer.example"},
			Documents: []platform.TrustDocument{{Kind: platform.DocVAPTReport, Visibility: platform.VisGated, Product: "p-checkout"}}},
	})
	for _, a := range []platform.Asset{
		{ID: "a-pay", TenantID: "t1", Type: "web_application", Target: "https://pay.acme.com"},
		{ID: "a-blog", TenantID: "t1", Type: "web_application", Target: "https://blog.acme.com"},
	} {
		_ = st.PutAsset(ctx, a)
		_ = st.PutEngagement(ctx, platform.Engagement{ID: "e-" + a.ID, TenantID: "t1", AssetID: a.ID, StartedAt: now, CompletedAt: now})
	}
	_ = st.PutFinding(ctx, "t1", types.Finding{ID: "f1", RuleID: "nuclei::sqli", Title: "SQL injection in checkout",
		Endpoint: "https://pay.acme.com/pay?id=1", AssetID: "a-pay", Severity: types.SeverityHigh, Tool: "nuclei"})
	_ = st.PutFinding(ctx, "t1", types.Finding{ID: "f2", RuleID: "nuclei::xss", Title: "Reflected XSS on the blog",
		Endpoint: "https://blog.acme.com/s?q=1", AssetID: "a-blog", Severity: types.SeverityHigh, Tool: "nuclei"})

	tn, _ := st.GetTenant(ctx, "t1")
	tok := d.trustTokenFor("t1", *tn.TrustCenter)
	var g struct {
		AccessToken string `json:"access_token"`
	}
	_ = json.Unmarshal(post(t, h, "/v1/trust/t1/request?token="+tok, `{"email":"jane@buyer.example"}`).Body.Bytes(), &g)
	if g.AccessToken == "" {
		t.Fatal("auto-approved access not granted")
	}

	// The listing names the product, so two such rows can be told apart.
	var view struct {
		Documents []struct {
			Title   string `json:"title"`
			Product string `json:"product"`
		} `json:"documents"`
	}
	_ = json.Unmarshal(get(t, h, "/v1/trust/t1?token="+tok+"&access="+g.AccessToken).Body.Bytes(), &view)
	if len(view.Documents) != 1 || view.Documents[0].Product != "p-checkout" || !strings.Contains(view.Documents[0].Title, "Checkout") {
		t.Fatalf("listing: %+v", view.Documents)
	}

	rec := get(t, h, "/v1/trust/t1/doc?token="+tok+"&kind=vapt_report&product=p-checkout&access="+g.AccessToken)
	body := rec.Body.String()
	if rec.Code != 200 || !strings.Contains(body, "SQL injection in checkout") {
		t.Fatalf("product report missing its finding: %d\n%s", rec.Code, body[:min(600, len(body))])
	}
	if strings.Contains(body, "Reflected XSS on the blog") {
		t.Error("a product-scoped report included a finding from an asset outside the product")
	}
	if !strings.Contains(body, "cto@acme.com") {
		t.Error("the report must say who confirmed the product's scope")
	}
	// Asking for the whole-workspace report is refused: none is configured.
	if rec := get(t, h, "/v1/trust/t1/doc?token="+tok+"&kind=vapt_report&access="+g.AccessToken); rec.Code == 200 {
		t.Error("a product-scoped row must not also serve the whole-workspace report")
	}

	// The product goes away: the report is withheld, never served for the whole workspace instead.
	tn, _ = st.GetTenant(ctx, "t1")
	tn.Products = nil
	_ = st.PutTenant(ctx, tn)
	if rec := get(t, h, "/v1/trust/t1/doc?token="+tok+"&kind=vapt_report&product=p-checkout&access="+g.AccessToken); rec.Code == 200 {
		t.Error("a report pinned to a product that no longer exists was served")
	}
	_ = json.Unmarshal(get(t, h, "/v1/trust/t1?token="+tok+"&access="+g.AccessToken).Body.Bytes(), &view)
	if len(view.Documents) != 0 {
		t.Errorf("an unavailable product report must not be listed: %+v", view.Documents)
	}
}
