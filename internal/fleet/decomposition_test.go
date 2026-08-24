package fleet

import (
	"fmt"
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/internal/webagent"
)

// TestDecompose_TierAndEnrichmentOrdering: the plan is intelligence-led — auth first, then a
// KEV-enriched seed before a plain seed, then a CVE probe, then a crown route, then residual. Ordering
// IS the bound (D4), so this order is the whole point.
func TestDecompose_TierAndEnrichmentOrdering(t *testing.T) {
	in := FrontierInput{
		Target: "https://app",
		Auth:   true,
		Seeds: []webagent.SeedFinding{
			{Route: "https://app/plain?q=1", Class: "xss", Severity: "medium"},
			{Route: "https://app/hot?id=1", Class: "sqli", Severity: "critical", Enrichment: "KEV weaponized av:network"},
		},
		CVEProbes:  []CVEProbe{{Route: "https://app/api", Class: "cve-2021-1234", Rank: 500}},
		Leads:      []webagent.EstateLead{{Route: "https://app/admin", Reaches: "admin identity", Evidence: []string{"e1"}}},
		Discovered: []string{"https://app/static/app.js", "https://app/blog?page=2"},
	}
	res := Decompose(in)
	got := make([]string, 0, len(res.Chunks))
	for _, c := range res.Chunks {
		got = append(got, fmt.Sprintf("t%d:%s", c.Tier, firstRoute(c)))
	}
	want := []string{
		"t5:https://app",             // auth
		"t4:https://app/hot?id=1",    // KEV+weaponized+critical seed
		"t4:https://app/plain?q=1",   // plain seed
		"t3:https://app/api",         // cve probe
		"t2:https://app/admin",       // crown
		"t1:https://app/blog?page=2", // residual (param-bearing; static .js dropped)
	}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("plan order wrong:\n got=%v\nwant=%v", got, want)
	}
	// The static asset was dropped, not ranked.
	for _, c := range res.Chunks {
		if strings.Contains(firstRoute(c), "app.js") {
			t.Error("static assets must be dropped from the residual tier")
		}
	}
}

// Determinism: same input → identical plan (chunk ids, order, scores).
func TestDecompose_Deterministic(t *testing.T) {
	in := FrontierInput{
		Target: "https://app",
		Seeds: []webagent.SeedFinding{
			{Route: "https://app/a?x=1", Class: "sqli", Severity: "high"},
			{Route: "https://app/b?y=1", Class: "xss", Severity: "high", Enrichment: "pub-exploit"},
		},
		Discovered: []string{"https://app/c?z=1", "https://app/d"},
	}
	a, b := Decompose(in), Decompose(in)
	if fmt.Sprint(a.Chunks) != fmt.Sprint(b.Chunks) {
		t.Errorf("Decompose is not deterministic:\n%v\n%v", a.Chunks, b.Chunks)
	}
}

// D5 vector 1: residual discovery is shape-deduped and hard-capped, and the overflow is COUNTED +
// DISCLOSED — never silently dropped, never explored.
func TestDecompose_OverflowDisclosedNotExplored(t *testing.T) {
	// 10 distinct-shape param routes + 5 index-variants of ONE shape.
	var disc []string
	for i := 0; i < 10; i++ {
		disc = append(disc, fmt.Sprintf("https://app/p%d?q=1", i))
	}
	for i := 1; i <= 5; i++ {
		disc = append(disc, fmt.Sprintf("https://app/items/%d", i)) // all collapse to /items/{id}
	}
	res := Decompose(FrontierInput{Target: "https://app", Discovered: disc, Caps: Caps{MaxRoutes: 4, MaxChunks: 50}})

	// Shape-dedup: the 5 /items/N collapse to 1 candidate; 10 distinct + 1 = 11 candidates, capped to 4.
	residualChunks := 0
	for _, c := range res.Chunks {
		if c.Tier == tierResidual {
			residualChunks++
		}
	}
	if residualChunks != 4 {
		t.Errorf("residual must be capped to MaxRoutes=4, got %d chunks", residualChunks)
	}
	if res.DroppedRoutes != 7 { // 11 candidates - 4 kept
		t.Errorf("dropped-route count wrong: got %d, want 7", res.DroppedRoutes)
	}
	if !strings.Contains(res.Disclosure, "NOT explored") || !strings.Contains(res.Disclosure, "disclosed") {
		t.Errorf("overflow must be disclosed honestly, got: %q", res.Disclosure)
	}
}

func TestDecompose_ChunkCapCutsTail(t *testing.T) {
	// One high-value seed + many residual; MaxChunks=2 keeps the seed and exactly one residual.
	var disc []string
	for i := 0; i < 20; i++ {
		disc = append(disc, fmt.Sprintf("https://app/r%d?q=1", i))
	}
	res := Decompose(FrontierInput{
		Target:     "https://app",
		Seeds:      []webagent.SeedFinding{{Route: "https://app/hot?id=1", Class: "sqli", Severity: "critical", Enrichment: "KEV"}},
		Discovered: disc,
		Caps:       Caps{MaxChunks: 2, MaxRoutes: 200},
	})
	if len(res.Chunks) != 2 {
		t.Fatalf("MaxChunks=2 must keep exactly 2 chunks, got %d", len(res.Chunks))
	}
	// The kept chunks must be the highest-scored: the seed is first.
	if res.Chunks[0].Tier != tierSeed {
		t.Errorf("the cap must cut the tail, not the head — seed chunk must survive, got tier %d", res.Chunks[0].Tier)
	}
	if res.DroppedChunks != 19 {
		t.Errorf("dropped-chunk count wrong: got %d, want 19", res.DroppedChunks)
	}
}

func TestUrlShape_CollapsesIndicesKeepsParamKeys(t *testing.T) {
	if urlShape("https://a/items/1") != urlShape("https://a/items/2") {
		t.Error("/items/1 and /items/2 must share a shape")
	}
	if urlShape("https://a/x?q=1") == urlShape("https://a/x?other=1") {
		t.Error("different param KEYS are different shapes (param presence is the surface)")
	}
	if urlShape("https://a/x?q=1") != urlShape("https://a/x?q=2") {
		t.Error("same param key, different VALUE must share a shape")
	}
}

func firstRoute(c Chunk) string {
	if len(c.Routes) == 0 {
		return ""
	}
	return c.Routes[0]
}
