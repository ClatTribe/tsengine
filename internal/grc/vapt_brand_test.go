package grc

import (
	"strings"
	"testing"
	"time"

	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// White-label: the report's PROSE carries the tenant's brand, and the ENGINE line — provenance,
// §10 pinned context — does not. A rebrand that erased what produced the assessment would be a
// claim about provenance rather than a coat of paint. Both renderers, both directions.
func TestVAPTRender_BrandsProseNotProvenance(t *testing.T) {
	fs := []types.Finding{{ID: "f1", RuleID: "r", Severity: types.SeverityHigh, Title: "SQLi", Endpoint: "https://acme.example/x", CWE: []string{"CWE-89"}}}
	rep := ReportFromFindings(fs, []string{"https://acme.example"}, "Acme", time.Now(), map[string]bool{"f1": true})

	md, html := RenderVAPTMarkdown(rep), RenderVAPTHTML(rep)
	for _, out := range []string{md, html} {
		if !strings.Contains(out, "performed by the "+platform.DefaultBrand+" engine") {
			t.Fatalf("unbranded report must read as the product's: %s", out[:200])
		}
	}

	rep.Brand = "Northwind Security"
	md, html = RenderVAPTMarkdown(rep), RenderVAPTHTML(rep)
	for _, out := range []string{md, html} {
		if !strings.Contains(out, "performed by the Northwind Security engine") {
			t.Errorf("branded report prose must carry the white-label")
		}
		if strings.Contains(out, "performed by the "+platform.DefaultBrand+" engine") {
			t.Errorf("branded report prose must not still name the product")
		}
		if !strings.Contains(out, rep.Engine) {
			t.Errorf("the engine identifier (%q) is provenance and must survive a rebrand", rep.Engine)
		}
	}
	if !strings.Contains(md, "Northwind Security has already prepared this fix") {
		t.Errorf("the fix-ready line must carry the brand too")
	}
}
