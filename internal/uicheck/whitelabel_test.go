package uicheck

import (
	"strings"
	"testing"
)

// whitelabel_test.go guards the READER half of white-label branding on the public Trust Center.
// A partner-branded page must render the partner's name and must NOT link to the product's own
// marketing site — that link names a company the buyer has never heard of, on the one page where
// there is no surrounding context to correct the impression. The default (unbranded) page keeps
// the link. FAILS rather than skips when the page moves (§14.2 rule 6).
func TestTrustPageRendersWhiteLabelAndDropsOurLinkWhenBranded(t *testing.T) {
	src := stripComments(frontendFile(t, "app", "trust", "[tenant]", "page.tsx"))
	for _, want := range []struct{ needle, why string }{
		{`data.white_labelled ?`, "the page must branch on the server's white_labelled bit, never re-derive it from the name"},
		{`{data.brand}`, "the brand name must be rendered from the server view"},
		{`data.brand_logo_url`, "a partner logo must be rendered when supplied"},
		{`Provided by {data.brand}`, "a branded page must say who provides it instead of linking to us"},
		{`Secured by {data.brand} — see how it works`, "the unbranded page keeps the product link"},
	} {
		if !strings.Contains(src, want.needle) {
			t.Errorf("trust page no longer contains %q — %s", want.needle, want.why)
		}
	}
	if strings.Contains(src, `>TensorShield<`) {
		t.Errorf("the trust page hard-codes the product name in chrome; it must render data.brand so a white-label takes effect")
	}
}
