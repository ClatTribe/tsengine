package web

import (
	"testing"

	"github.com/ClatTribe/tsengine/pkg/types"
)

func TestFilterSurface_DropsAndDedupes(t *testing.T) {
	target := types.Asset{Type: types.AssetWebApplication, Target: "https://x"}
	surface := []string{
		"https://x/",
		"https://x/style.css",         // static → drop
		"https://x/app.bundle.js",     // bundled JS → drop
		"https://x/items/1",           // shape /items/:int
		"https://x/items/2",           // dup shape → drop
		"https://x/items/3",           // dup shape → drop
		"https://x/admin/delete-user", // destructive → drop
		"https://x/logout",            // destructive → drop
		"https://attacker.com/evil",   // off-scope → drop
		"https://x/search?q=hi",       // kept
	}
	got := filterSurface(target, surface)
	// survivors: /, /items/1 (rep), /search?q=hi → 3
	if len(got) != 3 {
		t.Fatalf("got %d, want 3: %v", len(got), got)
	}
	want := map[string]bool{
		"https://x/":            true,
		"https://x/items/1":     true,
		"https://x/search?q=hi": true,
	}
	for _, u := range got {
		if !want[u] {
			t.Errorf("unexpected survivor %q", u)
		}
	}
}

func TestIsDestructivePath(t *testing.T) {
	drop := []string{
		"https://x/admin/delete-user", "https://x/logout",
		"https://x/items/remove/5", "https://x/account/destroy",
		"https://x/signout",
	}
	for _, u := range drop {
		if !isDestructivePath(u) {
			t.Errorf("expected destructive: %q", u)
		}
	}
	keep := []string{
		"https://x/items", "https://x/search?q=delete", // "delete" in query, not path
		"https://x/undelete-policy-docs", // not a /delete segment
	}
	for _, u := range keep {
		if isDestructivePath(u) {
			t.Errorf("should NOT be destructive: %q", u)
		}
	}
}

func TestPlanFanout_AppliesSurfaceFilter(t *testing.T) {
	h := NewHandler()
	// /items/1..3 collapse to one; dalfox only on the param URL.
	surface := []string{
		"https://x/items/1", "https://x/items/2", "https://x/items/3",
		"https://x/p?id=1",
		"https://x/logo.png", // dropped
	}
	out := h.PlanFanout(types.Asset{Type: types.AssetWebApplication, Target: "https://x"}, surface)
	dalfox := 0
	for _, d := range out {
		if d.Tool.Name() == "dalfox" {
			dalfox++
		}
	}
	// Only /p?id=1 has params → 1 dalfox dispatch (items collapsed + no params).
	if dalfox != 1 {
		t.Errorf("dalfox dispatches: got %d, want 1 (only the param URL after dedup)", dalfox)
	}
}
