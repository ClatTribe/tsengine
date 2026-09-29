package uicheck

import (
	"strings"
	"testing"
)

// The Products page is where a scope ends up on a report a customer's reviewer reads ("covers Acme App,
// confirmed by <name>"). These hold the screen to the refusals internal/productscope and the API make —
// a page that quietly dropped any of them would still compile and still look finished.
//
// FAILS rather than skips when a file moves (§14.2 rule 6): frontendFile fatals.

// A proposal is an inference; a product is a person's decision. The page must show WHO decided, and
// what each grouping rests on — otherwise a proposal and a confirmed scope read identically.
func TestProductsPageShowsWhoConfirmedAndWhatGroupingsRestOn(t *testing.T) {
	page := stripComments(frontendFile(t, "app", "(app)", "products", "page.tsx"))

	for _, want := range []struct{ field, why string }{
		{"p.confirmed_by", "a confirmed product never shows who confirmed it — the sentence the report hands a reviewer"},
		{"p.confirmed_at", "a confirmed product never shows when it was confirmed"},
		{"v.links_note", "the server's statement of what groupings rest on is never rendered"},
		{"l.why", "no proposal shows the concrete link behind each join, so an inference reads as a fact"},
		{"p.missing_asset_ids", "a product whose members disappeared would show a smaller scope than was confirmed, silently"},
		{"s.why", "a suggestion never says why the asset is linked to the product"},
		{"o.reason", "an out-of-scope asset never shows why it was excluded"},
		{"o.by", "an out-of-scope asset never shows who excluded it"},
	} {
		if !strings.Contains(page, want.field) {
			t.Errorf("products page never renders %s: %s", want.field, want.why)
		}
	}
}

// Infrastructure the platform cannot tie to a product must be offered for placement — never shown as a
// product of its own, and never labelled with a product-sounding confirm button.
func TestProductsPageNeverPresentsUnassignedInfrastructureAsAProduct(t *testing.T) {
	page := stripComments(frontendFile(t, "app", "(app)", "products", "page.tsx"))

	if !strings.Contains(page, "v.unassigned") {
		t.Fatal("the page never renders the unassigned groups — assets no proven link reaches would vanish")
	}
	i := strings.Index(page, "v.unassigned.map")
	if i < 0 {
		t.Fatal("unassigned groups are not rendered per group")
	}
	block := page[i:]
	if j := strings.Index(block, "v.out_of_scope"); j > 0 {
		block = block[:j]
	}
	if strings.Contains(block, "Confirm as a product") {
		t.Error("an unassigned group carries the proposal's confirm button — infrastructure we could not " +
			"tie to a product would be one click from becoming a product nobody identified")
	}
}

// Adding to a product REPLACES its membership server-side, so the action must carry the existing members
// and refuse when it cannot read them. Losing that would shrink a confirmed product on every add.
func TestAddToProductNeverDropsExistingMembers(t *testing.T) {
	actions := stripComments(frontendFile(t, "app", "(app)", "products", "actions.ts"))

	if !strings.Contains(actions, `"current"`) || !strings.Contains(actions, "current_${id}") {
		t.Error("addToProduct does not read the product's existing members from both forms that call it")
	}
	if !strings.Contains(actions, "current.length === 0") {
		t.Error("addToProduct does not refuse when it could not read the existing members — an add would " +
			"replace a confirmed product's scope with just the new asset")
	}
	if !strings.Contains(actions, "confirmer()") {
		t.Error("product writes are not attributed to the signed-in person")
	}
}
