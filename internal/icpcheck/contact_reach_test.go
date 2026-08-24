package icpcheck

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// contact_reach_test.go guards HOW A CUSTOMER REACHES A HUMAN.
//
// An audit found /contact built, well written, carrying a real email and phone — and linked only
// from the marketing nav and footer. Three places a person actually looks had nothing: the homepage
// body, the pricing page's own "Contact sales" button (which pointed at the lead FORM), and anywhere
// at all in the signed-in app, where the people already using the product are the ones most likely
// to need help.
//
// lib/contact.ts's own header says it fixed that "on nine pages". It missed these three, which is why
// the fix needs a guard and not just a commit.

func mustRead(t *testing.T, parts ...string) string {
	t.Helper()
	path := filepath.Join(append([]string{frontendDir(t)}, parts...)...)
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v — if this surface moved, move the guard with it rather than losing the check", path, err)
	}
	return string(b)
}

func TestContactIsReachableFromTheHomepageBody(t *testing.T) {
	// The nav and footer are chrome. A visitor reading the page and deciding to talk to someone should
	// not have to go hunting in the header for it.
	if !strings.Contains(mustRead(t, "app", "(marketing)", "page.tsx"), `href="/contact"`) {
		t.Error("the homepage body links /contact nowhere. Reachable only via nav/footer chrome means a " +
			"visitor who has just decided to talk to a human has to go looking.")
	}
}

func TestPricingContactSalesGoesToContactNotTheLeadForm(t *testing.T) {
	src := mustRead(t, "app", "(marketing)", "pricing", "page.tsx")
	if !strings.Contains(src, `cta: "Contact sales"`) {
		t.Skip("the Enterprise CTA was renamed; update this guard to match the new wording")
	}
	// Find the tier block containing the CTA and assert its href.
	i := strings.Index(src, `cta: "Contact sales"`)
	window := src[i:min(i+400, len(src))]
	if strings.Contains(window, `href: "/demo"`) {
		t.Error(`the pricing page says "Contact sales" and links /demo — the lead form. This is the page ` +
			"where a buyer with budget most wants an address and a phone number, and it is the exact " +
			"defect lib/contact.ts's header claims to have fixed elsewhere.")
	}
	if !strings.Contains(window, `href: "/contact"`) {
		t.Error(`"Contact sales" does not link /contact`)
	}
}

func TestSignedInAppCanReachAHuman(t *testing.T) {
	// The audit's sharpest contact finding: nothing in (app) linked /contact at all. The only
	// "contacts" in Settings is the tenant's OWN escalation roster, which is a different thing.
	src := mustRead(t, "components", "shell", "sidebar.tsx")
	if !strings.Contains(src, "/contact") {
		t.Error("the signed-in app shell offers no route to /contact. The people using the product are " +
			"the ones most likely to need us, and they had no way through.")
	}
}

func TestHomepageNamesTheCategoryAndTheBoundary(t *testing.T) {
	src := mustRead(t, "app", "(marketing)", "page.tsx")
	if !strings.Contains(strings.ToLower(src), "continuous exposure validation") {
		t.Error("the homepage never names the category it competes in, so a buyer who searches for it " +
			"cannot tell this is that product")
	}
	// The disqualifying half. A page that only says who should buy reads as a page hiding something.
	if !strings.Contains(src, "Do not buy this if") {
		t.Error("the homepage says who should buy and never who should not. Naming the boundary is the " +
			"strongest evidence the rest of the page is honest.")
	}
	for _, boundary := range []string{"internal network", "Kubernetes", "LLM"} {
		if !strings.Contains(src, boundary) {
			t.Errorf("the not-for-you list omits %q — one of the three surfaces we genuinely do not "+
				"cover, and the ones a buyer will otherwise assume are included", boundary)
		}
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
