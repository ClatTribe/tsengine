package grc

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// A product-scoped report covers the product's assets and nothing else — and says who confirmed that.
func TestVAPTReportFor_ScopesToTheConfirmedProduct(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	for _, a := range []platform.Asset{
		{ID: "app", TenantID: "t", Type: "web_application", Target: "https://app.acme.com"},
		{ID: "mkt", TenantID: "t", Type: "web_application", Target: "https://www.acme.com"},
		// A MORE SPECIFIC asset outside the product, under a member's target: longest-match must win.
		{ID: "admin", TenantID: "t", Type: "web_application", Target: "https://app.acme.com/admin"},
	} {
		if err := st.PutAsset(ctx, a); err != nil {
			t.Fatal(err)
		}
	}
	for _, f := range []types.Finding{
		{ID: "f-app", Endpoint: "https://app.acme.com/login", Severity: types.SeverityHigh, RuleID: "r1", Title: "a"},
		{ID: "f-mkt", Endpoint: "https://www.acme.com/", Severity: types.SeverityCritical, RuleID: "r2", Title: "b"},
		{ID: "f-admin", Endpoint: "https://app.acme.com/admin/users", Severity: types.SeverityCritical, RuleID: "r3", Title: "c"},
		{ID: "f-lost", Endpoint: "lib/util.go:12", Severity: types.SeverityHigh, RuleID: "r4", Title: "d"},
	} {
		if err := st.PutFinding(ctx, "t", f); err != nil {
			t.Fatal(err)
		}
	}
	when := time.Date(2026, 9, 30, 0, 0, 0, 0, time.UTC)
	g := &GRC{Store: st, Now: func() time.Time { return when }}

	rep, err := g.VAPTReportFor(ctx, "t", &ProductScope{Name: "Acme App", AssetIDs: []string{"app"},
		ConfirmedBy: "Priya Shah", ConfirmedAt: when})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Summary.Total != 1 || rep.Findings[0].ID != "f-app" {
		var ids []string
		for _, f := range rep.Findings {
			ids = append(ids, f.ID)
		}
		t.Fatalf("want only f-app (not the marketing site, not the more-specific admin asset): got %v", ids)
	}
	if len(rep.Scope) != 1 || rep.Scope[0] != "https://app.acme.com" {
		t.Fatalf("scope must list only the product's assets: %v", rep.Scope)
	}
	if !strings.Contains(rep.ScopeStatement, "Priya Shah") || !strings.Contains(rep.ScopeStatement, "Acme App") {
		t.Fatalf("the report must say who confirmed the scope: %q", rep.ScopeStatement)
	}
	if rep.UnattributedExcluded != 1 {
		t.Fatalf("the unattributable finding must be DISCLOSED, not silently dropped: %d", rep.UnattributedExcluded)
	}
	md := RenderVAPTMarkdown(rep)
	if !strings.Contains(md, "Priya Shah") || !strings.Contains(md, "could not be attributed") {
		t.Fatal("the markdown deliverable must carry the scope statement and the disclosure")
	}
	if !strings.Contains(RenderVAPTHTML(rep), "Priya Shah") {
		t.Fatal("the HTML deliverable must carry the scope statement")
	}

	// The workspace-wide report is unchanged: every finding, no product statement.
	all, err := g.VAPTReport(ctx, "t")
	if err != nil {
		t.Fatal(err)
	}
	if all.Summary.Total != 4 || all.ScopeStatement != "" || all.UnattributedExcluded != 0 {
		t.Fatalf("workspace report must be unaffected: total=%d stmt=%q", all.Summary.Total, all.ScopeStatement)
	}
}

// Another product's confirmed fix is not evidence about this one.
func TestVAPTReportFor_RetestRollupCountsOnlyThisProductsFixes(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	_ = st.PutAsset(ctx, platform.Asset{ID: "a", TenantID: "t", Type: "web_application", Target: "https://a.acme.com"})
	_ = st.PutAsset(ctx, platform.Asset{ID: "b", TenantID: "t", Type: "web_application", Target: "https://b.other.io"})
	_ = st.PutFinding(ctx, "t", types.Finding{ID: "fa", Endpoint: "https://a.acme.com/x", Severity: types.SeverityHigh, RuleID: "r"})
	_ = st.PutFinding(ctx, "t", types.Finding{ID: "fb", Endpoint: "https://b.other.io/x", Severity: types.SeverityHigh, RuleID: "r"})
	_ = st.PutAction(ctx, platform.Action{ID: "act-b", TenantID: "t", FindingID: "fb",
		Verification: &platform.FixVerification{Status: platform.FixStatusFixed}})
	g := &GRC{Store: st, Now: time.Now}

	rep, err := g.VAPTReportFor(ctx, "t", &ProductScope{Name: "A", AssetIDs: []string{"a"}, ConfirmedBy: "x", ConfirmedAt: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Summary.RetestConfirmed != 0 {
		t.Fatalf("product A must not claim product B's confirmed fix: %d", rep.Summary.RetestConfirmed)
	}
	all, _ := g.VAPTReport(ctx, "t")
	if all.Summary.RetestConfirmed != 1 {
		t.Fatalf("the workspace report still counts it: %d", all.Summary.RetestConfirmed)
	}
}
