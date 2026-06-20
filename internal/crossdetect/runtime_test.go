package crossdetect

import (
	"testing"

	"github.com/ClatTribe/tsengine/pkg/platform"
)

func TestHttpPath(t *testing.T) {
	cases := map[string]string{
		"https://app.acme.com/search?q=x": "/search",
		"http://app.acme.com/a/b/":        "/a/b",
		"/search":                         "/search",
		"/login?next=/":                   "/login",
		"app.acme.com":                    "", // bare host → no path
		"https://app.acme.com/":           "/",
	}
	for in, want := range cases {
		if got := httpPath(in); got != want {
			t.Errorf("httpPath(%q)=%q want %q", in, got, want)
		}
	}
}

func TestAnnotateRuntime(t *testing.T) {
	issues := []Issue{
		{Key: "rule|/search", Endpoint: "https://app.acme.com/search?q="}, // attacked
		{Key: "rule|/admin", Endpoint: "https://app.acme.com/admin"},      // not attacked
		{Key: "CVE-2021-23337", CVE: "CVE-2021-23337", Endpoint: ""},      // SCA issue, no endpoint → never attacked
	}
	events := []platform.RuntimeEvent{
		{Endpoint: "/search", AttackKind: "sql_injection", Blocked: true},
		{Endpoint: "https://app.acme.com/search", AttackKind: "sql_injection", Blocked: true},
		{Endpoint: "/unrelated", AttackKind: "xss"},
	}
	flagged := AnnotateRuntime(issues, events)
	if flagged != 1 {
		t.Fatalf("want 1 attacked issue, got %d", flagged)
	}
	if !issues[0].Attacked || issues[0].AttackCount != 2 {
		t.Errorf("/search issue should be attacked x2, got attacked=%v count=%d", issues[0].Attacked, issues[0].AttackCount)
	}
	if issues[1].Attacked || issues[2].Attacked {
		t.Error("non-matching and endpoint-less issues must not be flagged")
	}

	// No events → nothing flagged, no mutation.
	fresh := []Issue{{Key: "x", Endpoint: "/search"}}
	if n := AnnotateRuntime(fresh, nil); n != 0 || fresh[0].Attacked {
		t.Error("no events should flag nothing")
	}
}
