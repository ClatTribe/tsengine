package platformapi

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/internal/connector"
	"github.com/ClatTribe/tsengine/internal/crossdetect"
	"github.com/ClatTribe/tsengine/internal/grc"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

func productsHarness(t *testing.T) (http.Handler, store.Store) {
	t.Helper()
	ctx := context.Background()
	st := store.NewMemory()
	for _, tn := range []string{"t1", "t2"} {
		if err := st.PutTenant(ctx, platform.Tenant{ID: tn, Name: tn}); err != nil {
			t.Fatal(err)
		}
	}
	for _, a := range []platform.Asset{
		{ID: "web", TenantID: "t1", Type: "web_application", Target: "https://app.acme.com"},
		{ID: "api", TenantID: "t1", Type: "api", Target: "https://api.acme.com"},
		{ID: "mkt", TenantID: "t1", Type: "web_application", Target: "https://www.acme.com"},
		{ID: "repo", TenantID: "t1", Type: "repository", Target: "https://github.com/acme/app"},
		{ID: "other", TenantID: "t2", Type: "web_application", Target: "https://app.other.io"},
	} {
		if err := st.PutAsset(ctx, a); err != nil {
			t.Fatal(err)
		}
	}
	h := NewHandler(Deps{Store: st, Connectors: connector.NewRegistry(), Token: "platform-tok",
		GRC: &grc.GRC{Store: st}})
	return h, st
}

func decodeProducts(t *testing.T, body []byte) productsResponse {
	t.Helper()
	var out productsResponse
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("decode: %v: %s", err, body)
	}
	return out
}

func TestProducts_ProposesFromTheRegisteredDomainAndLeavesInfraUnassigned(t *testing.T) {
	h, _ := productsHarness(t)
	rec := do(h, "GET", "/v1/products", "t1", "")
	if rec.Code != 200 {
		t.Fatalf("GET /v1/products: %d %s", rec.Code, rec.Body)
	}
	out := decodeProducts(t, rec.Body.Bytes())
	if len(out.Proposals) != 1 || out.Proposals[0].Name != "acme.com" || len(out.Proposals[0].Assets) != 3 {
		t.Fatalf("want one proposal acme.com with app, api and www: %+v", out.Proposals)
	}
	if len(out.Unassigned) != 1 || out.Unassigned[0].Assets[0].ID != "repo" {
		t.Fatalf("the repository has no provable link — it must be left unassigned: %+v", out.Unassigned)
	}
	if out.LinksNote == "" {
		t.Fatal("the grouping basis must be stated alongside the proposals")
	}
	for _, p := range out.Proposals {
		for _, a := range p.Assets {
			if a.ID == "other" {
				t.Fatal("another tenant's asset appeared in a proposal")
			}
		}
	}
}

func TestProducts_ConfirmRequiresANamedHumanAndOwnAssets(t *testing.T) {
	h, _ := productsHarness(t)
	if rec := do(h, "POST", "/v1/products", "t1", `{"name":"Acme App","asset_ids":["web","api"]}`); rec.Code != 400 {
		t.Fatalf("no confirmed_by must be refused: %d %s", rec.Code, rec.Body)
	}
	// Another tenant's asset id is not a member (isolation, §18.2 inv. 2).
	if rec := do(h, "POST", "/v1/products", "t1", `{"name":"Acme App","asset_ids":["web","other"],"confirmed_by":"Priya"}`); rec.Code != 400 ||
		!strings.Contains(rec.Body.String(), "unknown asset ids") {
		t.Fatalf("a foreign asset id must be refused: %d %s", rec.Code, rec.Body)
	}
	rec := do(h, "POST", "/v1/products", "t1", `{"name":"Acme App","asset_ids":["web"],"confirmed_by":"Priya Shah"}`)
	if rec.Code != 200 {
		t.Fatalf("confirm: %d %s", rec.Code, rec.Body)
	}
	out := decodeProducts(t, do(h, "GET", "/v1/products", "t1", "").Body.Bytes())
	if len(out.Products) != 1 || out.Products[0].ConfirmedBy != "Priya Shah" || len(out.Products[0].Assets) != 1 {
		t.Fatalf("confirmed product not listed: %+v", out.Products)
	}
	// api and www are linked into the confirmed product — SUGGESTED, never added.
	if got := len(out.Products[0].Suggestions); got != 2 {
		t.Fatalf("want api + www suggested for the confirmed product, got %d: %+v", got, out.Products[0].Suggestions)
	}
	if len(out.Proposals) != 0 {
		t.Fatalf("assets suggested for a confirmed product must not also be re-proposed: %+v", out.Proposals)
	}
	// The other tenant sees none of it.
	if other := decodeProducts(t, do(h, "GET", "/v1/products", "t2", "").Body.Bytes()); len(other.Products) != 0 {
		t.Fatalf("tenant t2 must not see t1's products: %+v", other.Products)
	}
}

func TestProducts_OutOfScopeNeedsAReasonGiverAndCannotHideAMember(t *testing.T) {
	h, _ := productsHarness(t)
	do(h, "POST", "/v1/products", "t1", `{"name":"Acme App","asset_ids":["web"],"confirmed_by":"Priya"}`)

	if rec := do(h, "POST", "/v1/products/scope", "t1", `{"asset_id":"mkt","out_of_scope":true}`); rec.Code != 400 {
		t.Fatalf("excluding without a named person must be refused: %d", rec.Code)
	}
	if rec := do(h, "POST", "/v1/products/scope", "t1", `{"asset_id":"web","out_of_scope":true,"by":"Priya"}`); rec.Code != 400 {
		t.Fatalf("a product member cannot be silently excluded: %d %s", rec.Code, rec.Body)
	}
	if rec := do(h, "POST", "/v1/products/scope", "t1", `{"asset_id":"mkt","out_of_scope":true,"by":"Priya","reason":"marketing site"}`); rec.Code != 200 {
		t.Fatalf("exclude: %d %s", rec.Code, rec.Body)
	}
	out := decodeProducts(t, do(h, "GET", "/v1/products", "t1", "").Body.Bytes())
	if len(out.OutOfScope) != 1 || out.OutOfScope[0].Reason != "marketing site" || out.OutOfScope[0].By != "Priya" {
		t.Fatalf("the exclusion must be recorded with who and why: %+v", out.OutOfScope)
	}
	for _, s := range out.Products[0].Suggestions {
		if s.Asset.ID == "mkt" {
			t.Fatal("an out-of-scope asset must not be suggested")
		}
	}
	if rec := do(h, "POST", "/v1/products", "t1", `{"name":"Marketing","asset_ids":["mkt"],"confirmed_by":"Priya"}`); rec.Code != 400 {
		t.Fatalf("an out-of-scope asset cannot join a product until it is brought back: %d", rec.Code)
	}
}

func TestProducts_ExposureAgreesWithTheIssuesIdentity(t *testing.T) {
	h, st := productsHarness(t)
	ctx := context.Background()
	// Two tools, one issue — counted once. An ignored issue is not counted at all.
	dup1 := types.Finding{ID: "f1", AssetID: "web", RuleID: "sqli", Endpoint: "https://app.acme.com/q", Severity: types.SeverityHigh, Tool: "nuclei"}
	dup2 := types.Finding{ID: "f2", AssetID: "web", RuleID: "sqli", Endpoint: "https://app.acme.com/q", Severity: types.SeverityCritical, Tool: "sqlmap"}
	ign := types.Finding{ID: "f3", AssetID: "web", RuleID: "xss", Endpoint: "https://app.acme.com/s", Severity: types.SeverityMedium}
	for _, f := range []types.Finding{dup1, dup2, ign} {
		_ = st.PutFinding(ctx, "t1", f)
	}
	_ = st.PutIgnoreRule(ctx, platform.IgnoreRule{TenantID: "t1", IssueKey: crossdetect.DedupKey(ign), Reason: "false_positive"})
	do(h, "POST", "/v1/products", "t1", `{"name":"Acme App","asset_ids":["web"],"confirmed_by":"Priya"}`)

	out := decodeProducts(t, do(h, "GET", "/v1/products", "t1", "").Body.Bytes())
	e := out.Products[0].Exposure
	if e.Total != 1 || e.Critical != 1 {
		t.Fatalf("want 1 distinct issue at its WORST severity (critical), ignored one excluded: %+v", e)
	}
}

func TestProducts_VAPTReportScopedToAProduct(t *testing.T) {
	h, st := productsHarness(t)
	ctx := context.Background()
	_ = st.PutFinding(ctx, "t1", types.Finding{ID: "fw", AssetID: "web", RuleID: "r1", Endpoint: "https://app.acme.com/x", Severity: types.SeverityHigh, Title: "in product"})
	_ = st.PutFinding(ctx, "t1", types.Finding{ID: "fm", AssetID: "mkt", RuleID: "r2", Endpoint: "https://www.acme.com/x", Severity: types.SeverityHigh, Title: "not in product"})
	rec := do(h, "POST", "/v1/products", "t1", `{"name":"Acme App","asset_ids":["web"],"confirmed_by":"Priya Shah"}`)
	var p platform.Product
	_ = json.Unmarshal(rec.Body.Bytes(), &p)

	if rec := do(h, "GET", "/v1/vapt/report?product=nope&format=json", "t1", ""); rec.Code != 404 {
		t.Fatalf("an unknown product must 404, not silently fall back to the workspace: %d", rec.Code)
	}
	rec = do(h, "GET", "/v1/vapt/report?product="+p.ID+"&format=json", "t1", "")
	if rec.Code != 200 {
		t.Fatalf("scoped report: %d %s", rec.Code, rec.Body)
	}
	var rep grc.VAPTReport
	_ = json.Unmarshal(rec.Body.Bytes(), &rep)
	if rep.Summary.Total != 1 || rep.Product != "Acme App" || !strings.Contains(rep.ScopeStatement, "Priya Shah") {
		t.Fatalf("want 1 finding, product named, confirmer stated: total=%d product=%q stmt=%q", rep.Summary.Total, rep.Product, rep.ScopeStatement)
	}
	// Tenant t2 cannot request t1's product.
	if rec := do(h, "GET", "/v1/vapt/report?product="+p.ID+"&format=json", "t2", ""); rec.Code != 404 {
		t.Fatalf("another tenant's product id must 404: %d", rec.Code)
	}
}

func TestProducts_EveryChangeReconfirms(t *testing.T) {
	h, _ := productsHarness(t)
	rec := do(h, "POST", "/v1/products", "t1", `{"name":"Acme App","asset_ids":["web"],"confirmed_by":"Priya"}`)
	var p platform.Product
	_ = json.Unmarshal(rec.Body.Bytes(), &p)
	if rec := do(h, "PUT", "/v1/products/"+p.ID, "t1", `{"asset_ids":["web","api"]}`); rec.Code != 400 {
		t.Fatalf("a membership change without a named confirmer must be refused: %d", rec.Code)
	}
	rec = do(h, "PUT", "/v1/products/"+p.ID, "t1", `{"asset_ids":["web","api"],"confirmed_by":"Ravi"}`)
	var up platform.Product
	_ = json.Unmarshal(rec.Body.Bytes(), &up)
	if rec.Code != 200 || up.ConfirmedBy != "Ravi" || len(up.AssetIDs) != 2 {
		t.Fatalf("the changed scope must carry its new confirmer: %d %+v", rec.Code, up)
	}
}
