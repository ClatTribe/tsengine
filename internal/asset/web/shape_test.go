package web

import "testing"

func TestCanonicalizePath(t *testing.T) {
	cases := map[string]string{
		"/items/42":                              "/items/:int",
		"/users/9999/posts/3":                    "/users/:int/posts/:int",
		"/o/550e8400-e29b-41d4-a716-446655440000": "/o/:uuid",
		"/files/a1b2c3d4e5f60718":                "/files/:hash",
		"/reports/2026-05-29":                    "/reports/:date",
		"/search":                                "/search",   // content, not id — preserved
		"/api/users":                             "/api/users", // preserved
		"":                                       "/",
	}
	for in, want := range cases {
		if got := canonicalizePath(in); got != want {
			t.Errorf("canonicalizePath(%q): got %q, want %q", in, got, want)
		}
	}
}

func TestDedupeByShape(t *testing.T) {
	urls := []string{
		"https://x/items/1",
		"https://x/items/2",
		"https://x/items/3",
		"https://x/search?q=a",
		"https://x/search?q=b", // same shape as previous (query value differs)
		"https://x/users/5",
		"https://x/users/6",
		"https://x/about", // distinct content endpoint
	}
	got := dedupeByShape(urls)
	// shapes: /items/:int, /search?{q}, /users/:int, /about → 4 representatives
	if len(got) != 4 {
		t.Fatalf("got %d after dedup, want 4: %v", len(got), got)
	}
	// First-seen preserved.
	if got[0] != "https://x/items/1" || got[1] != "https://x/search?q=a" {
		t.Errorf("dedup order wrong: %v", got)
	}
}

func TestShapeKey_QueryNamesNotValues(t *testing.T) {
	if shapeKey("https://x/p?id=1") != shapeKey("https://x/p?id=2") {
		t.Error("same query name, different value → same shape")
	}
	if shapeKey("https://x/p?id=1") == shapeKey("https://x/p?other=1") {
		t.Error("different query name → different shape")
	}
}

func TestShapeKey_HostMatters(t *testing.T) {
	if shapeKey("https://a/x") == shapeKey("https://b/x") {
		t.Error("different host → different shape")
	}
}
