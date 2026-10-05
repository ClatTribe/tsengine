package uicheck

import (
	"strings"
	"testing"
)

// A product-scoped penetration test report is a different document from the workspace-wide one. The buyer
// page's link must carry the product, or every click on that row is refused by the server and reads to the
// buyer as a broken page. FAILS rather than skips when the file moves (§14.2 rule 6).
func TestTrustBuyerLinkCarriesTheProduct(t *testing.T) {
	src := stripComments(frontendFile(t, "components", "trust", "document-tier.tsx"))
	if !strings.Contains(src, `if (e.product) q.set("product", e.product);`) {
		t.Error("the buyer document link drops the product, so a product-scoped report can never be opened")
	}
}
