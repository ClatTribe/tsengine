// Package viewportcheck holds no runtime code. Like internal/uicheck and internal/legalcheck, it
// gates a frontend contract from Go, because the frontend has no test runner (its CI job is lint +
// typecheck + build) while `go test ./...` runs on every PR.
//
// WHAT IT GUARDS (ADR 0022 §1). The app shipped for a long time with no responsive treatment at
// all: the sidebar was `flex w-56 shrink-0` at every width, which left 151px for the whole
// application at 375px, with no hamburger and no collapse. The Inbox — the approval queue a founder
// opens when Slack says "3 fixes ready for your approval" — could not be operated on the device
// they were holding.
//
// The fix is three classes and a context. All three are easy to delete during an unrelated refactor
// and impossible to notice on a 1440px monitor, which is the exact shape of the original defect:
// invisible to the person writing the code, obvious to the person holding the phone.
package viewportcheck

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func repoFile(t *testing.T, rel string) string {
	t.Helper()
	p, err := filepath.Abs(filepath.Join("..", "..", rel))
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(p)
	if err != nil {
		t.Skipf("%s not present (%v) — skipping viewport guard", rel, err)
	}
	return string(b)
}

// The shell must keep a mobile mode: a sidebar that hides below the breakpoint, and a trigger that
// brings it back. Either one alone is useless — a hidden sidebar with no trigger is a lost nav, and
// a trigger with a permanently-visible sidebar is a no-op.
func TestShellKeepsItsMobileMode(t *testing.T) {
	sidebar := repoFile(t, "frontend/components/shell/sidebar.tsx")
	if !strings.Contains(sidebar, "hidden md:flex") {
		t.Error("the sidebar no longer hides below md.\n" +
			"Without it the sidebar holds 224px at every width and the app gets 151px at 375px — the " +
			"state ADR 0022 §1 exists to prevent. Restore `hidden md:flex` on the <aside>.")
	}
	if !strings.Contains(sidebar, "mobileNavOpen") {
		t.Error("the sidebar no longer opens as a drawer — nothing reads the mobile-nav state, so a " +
			"phone user has a hidden sidebar and no way to show it")
	}

	topbar := repoFile(t, "frontend/components/shell/topbar.tsx")
	if !strings.Contains(topbar, "MobileNavTrigger") {
		t.Error("the TopBar no longer renders MobileNavTrigger — the sidebar hides below md and " +
			"nothing brings it back, which is worse than the original defect: navigation becomes " +
			"unreachable rather than merely cramped")
	}

	layout := repoFile(t, "frontend/app/(app)/layout.tsx")
	for _, need := range []string{"MobileNavProvider", "MobileNavBackdrop"} {
		if !strings.Contains(layout, need) {
			t.Errorf("the app shell no longer mounts %s — the trigger and the drawer are sibling "+
				"client components with a server component between them, so without the provider "+
				"they share no state and the trigger silently does nothing", need)
		}
	}
}

// The trigger must stay finger-sized. It is the one control that unlocks every other control on a
// phone, so it is the last place to save 8px.
func TestMobileTriggerStaysTouchSized(t *testing.T) {
	src := repoFile(t, "frontend/components/shell/mobile-nav.tsx")
	// h-11/w-11 is 44px at the default 16px root — the WCAG target-size floor.
	if !strings.Contains(src, "h-11 w-11") {
		t.Error("the mobile nav trigger is no longer 44px (h-11 w-11).\n" +
			"It is the only way to reach navigation on a phone; below 44px it becomes a control " +
			"people miss, on the screen where they have the fewest alternatives.")
	}
}
