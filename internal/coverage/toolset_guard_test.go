package coverage_test

import (
	"sort"
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/internal/assetregistry"
	"github.com/ClatTribe/tsengine/internal/coverage"
	_ "github.com/ClatTribe/tsengine/internal/toolsbundle" // registers every wrapper (§16)
	"github.com/ClatTribe/tsengine/pkg/types"
)

// reconAndFanout names tools that DO run on every scan of an asset but are not in its anchor set,
// because they are dispatched by Recon() or PlanFanout() rather than PlanAnchors(). They belong in
// Toolset — the customer-facing question is "did this run", not "which code path dispatched it".
//
// Hand-maintained ON PURPOSE. Every entry is a claim that this tool really fires unconditionally, and
// making that claim should be a deliberate edit rather than something a wildcard absorbs.
var reconAndFanout = map[types.AssetType][]string{
	types.AssetWebApplication: {"katana"},                     // Recon(): the crawl that produces the surface
	types.AssetIPAddress:      {"naabu", "nuclei"},            // Recon(): port discovery → per-port nuclei fan-out
	types.AssetDomain:         {"amass", "dnstwist", "httpx"}, // Recon() enum + unconditional breadth + fan-out
}

func names(t *testing.T, at types.AssetType) map[string]bool {
	t.Helper()
	h, err := assetregistry.HandlerFor(at)
	if err != nil {
		t.Fatalf("no handler for %s: %v", at, err)
	}
	out := map[string]bool{}
	for _, tl := range h.Anchors() {
		out[tl.Name()] = true
	}
	return out
}

// coverage.Toolset is what /coverage tells a customer actually ran. It is hand-mirrored from the
// asset handlers, and hand-mirrored lists drift — this one had, in BOTH directions, with nothing
// checking it.
//
// Under-declaring understates the work and is merely wrong. OVER-declaring names a tool that did not
// run on the page built to answer "what was actually tested", which is the one direction §10 forbids.
func TestToolsetMatchesTheHandlersItMirrors(t *testing.T) {
	checked := 0
	for _, at := range types.AllAssetTypes() {
		declared, ok := coverage.Toolset[string(at)]
		if !ok {
			continue // workspace/mobile handled elsewhere; a missing entry is its own decision
		}
		anchors := names(t, at)
		if len(anchors) == 0 {
			continue // no handler-declared anchors to compare against
		}
		checked++
		decl := map[string]bool{}
		for _, d := range declared {
			decl[d] = true
		}
		allowed := map[string]bool{}
		for k := range anchors {
			allowed[k] = true
		}
		for _, k := range reconAndFanout[at] {
			allowed[k] = true
		}

		var missing, extra []string
		for a := range anchors {
			if !decl[a] {
				missing = append(missing, a)
			}
		}
		for d := range decl {
			if !allowed[d] {
				extra = append(extra, d)
			}
		}
		sort.Strings(missing)
		sort.Strings(extra)
		if len(missing) > 0 {
			t.Errorf("%s: /coverage OMITS anchor tools that really run: %s\n"+
				"The page understates what was tested.", at, strings.Join(missing, ", "))
		}
		if len(extra) > 0 {
			t.Errorf("%s: /coverage CLAIMS tools that are not anchors and not unconditional recon/"+
				"fan-out: %s\nOn the page that answers \"what was actually tested\", naming a tool that "+
				"fires only conditionally is the overstatement direction (§10). If one of these really "+
				"does fire on every scan, add it to reconAndFanout with the reason.",
				at, strings.Join(extra, ", "))
		}
	}
	// §14.2 rule 6: a guard that compared nothing must fail rather than pass.
	if checked == 0 {
		t.Fatal("no asset type was compared: this guard cannot see its subject")
	}
}
