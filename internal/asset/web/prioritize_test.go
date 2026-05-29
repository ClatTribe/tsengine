package web

import (
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/pkg/types"
)

func TestSelectSurface_FiltersAndPrioritizesBeforeCap(t *testing.T) {
	h := NewHandler()
	target := types.Asset{Type: types.AssetWebApplication, Target: "https://app.test/"}

	// Raw order deliberately puts noise FIRST: a naive dedupe-then-cap (the
	// old bug) would keep the css/js/png and truncate the real param URLs.
	raw := []string{
		"https://app.test/",           // bare root, no params (low value)
		"https://app.test/style.css",  // static noise
		"https://app.test/app.js",     // static noise
		"https://app.test/logo.png",   // static noise
		"https://evil.com/x?id=1",     // off-scope
		"https://app.test/logout?u=1", // destructive path
		"https://app.test/search?q=1", // PARAM — high value
		"https://app.test/item?id=2",  // PARAM — high value
	}

	got := h.SelectSurface(target, raw, 3)

	if len(got) > 3 {
		t.Fatalf("cap not applied: got %d", len(got))
	}
	for _, u := range got {
		if strings.Contains(u, "evil.com") {
			t.Errorf("off-scope URL survived: %s", u)
		}
		if strings.HasSuffix(u, ".css") || strings.HasSuffix(u, ".js") || strings.HasSuffix(u, ".png") {
			t.Errorf("static asset survived: %s", u)
		}
		if strings.Contains(u, "logout") {
			t.Errorf("destructive path survived: %s", u)
		}
	}
	// The two param URLs are highest-value → must survive the cap-of-3 even
	// though they appear LAST in the raw crawl order.
	want := map[string]bool{"https://app.test/search?q=1": true, "https://app.test/item?id=2": true}
	found := 0
	for _, u := range got {
		if want[u] {
			found++
		}
	}
	if found != 2 {
		t.Errorf("both param URLs should survive the cap; got %v", got)
	}
	// And the param URLs should rank ABOVE the bare root.
	if got[0] == "https://app.test/" {
		t.Errorf("bare root should not outrank param URLs: %v", got)
	}
}

func TestScoreURL_ParamBeatsParamless(t *testing.T) {
	if scoreURL("https://x/p?id=1") <= scoreURL("https://x/p") {
		t.Error("a param-bearing URL must outscore a paramless one")
	}
}
