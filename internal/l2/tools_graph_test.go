package l2

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// fakeGraph is a scripted traversal surface.
type fakeGraph struct {
	hops      []GraphHop
	paths     []GraphPath
	truncated bool
	why       []GraphHop
	cps       []GraphChokePoint
	err       error
}

func (f fakeGraph) Neighbors(context.Context, string) ([]GraphHop, error) {
	return f.hops, f.err
}
func (f fakeGraph) PathsFrom(context.Context, string) ([]GraphPath, bool, error) {
	return f.paths, f.truncated, f.err
}
func (f fakeGraph) Why(context.Context, string, string) ([]GraphHop, error) { return f.why, f.err }
func (f fakeGraph) ChokePoints(context.Context) ([]GraphChokePoint, error)  { return f.cps, f.err }

func callGraph(t *testing.T, g EstateGraph, args map[string]any) string {
	t.Helper()
	c := GraphTools(g)
	if len(c) != 1 {
		t.Fatalf("expected exactly 1 traversal slot, got %d", len(c))
	}
	res, err := c[0].Handler(context.Background(), args, &State{})
	if err != nil {
		t.Fatalf("handler errored: %v", err)
	}
	return res.Content
}

// ── THE CAP (§2.6) ───────────────────────────────────────────────────────────────────────────────
//
// The existing cap tests wire the engineer belt and no graph, so they would happily pass while the
// graph slot pushed a phase over the limit. This is the one that actually exercises the risk.
func TestGraphTool_CapHoldsWithTheFullBeltWired(t *testing.T) {
	d := Deps{
		Engineer: EngineerTools(nil, nil, nil, nil, nil, nil),
		Graph:    fakeGraph{},
	}
	c := BuildCatalog(d)
	if err := c.Validate(); err != nil {
		t.Fatalf("belt + graph must still satisfy the cap: %v", err)
	}
	for _, p := range []Phase{PhaseTriage, PhaseInvestigate, PhaseChain, PhaseReport} {
		if n := len(c.exposedIn(p)); n > 12 {
			t.Errorf("phase %s exposes %d tools with the graph wired — over the cap", p, n)
		}
	}
}

// Four separate traversal tools would have eaten a third of the belt. One slot, four ops — the
// dispatch_l2_probe pattern.
func TestGraphTool_IsASingleSlot(t *testing.T) {
	if n := len(GraphTools(fakeGraph{})); n != 1 {
		t.Errorf("graph added %d catalogue slots, want 1", n)
	}
}

// Traversal is how you build a chain; it is noise during triage.
func TestGraphTool_ScopedToInvestigateAndChain(t *testing.T) {
	c := BuildCatalog(Deps{Graph: fakeGraph{}})
	in := func(p Phase) bool {
		for _, s := range c.exposedIn(p) {
			if s.Name == "traverse_estate" {
				return true
			}
		}
		return false
	}
	if !in(PhaseInvestigate) || !in(PhaseChain) {
		t.Error("traverse_estate is unreachable in investigate/chain — the agent can never walk the graph")
	}
	if in(PhaseTriage) {
		t.Error("traverse_estate is exposed during triage, spending cap where it is not useful")
	}
}

// Unwired must cost nothing — a deployment with no graph should not spend cap on a tool that can only
// answer "not available".
func TestGraphTool_UnwiredAddsNothing(t *testing.T) {
	if got := len(GraphTools(nil)); got != 0 {
		t.Errorf("nil graph produced %d tools", got)
	}
	base := len(BuildCatalog(Deps{}))
	if got := len(BuildCatalog(Deps{Graph: nil})); got != base {
		t.Errorf("nil Graph changed the catalog size (%d vs %d)", got, base)
	}
	if got := len(BuildCatalog(Deps{Graph: fakeGraph{}})); got != base+1 {
		t.Errorf("wired graph added %d tools, want exactly 1", got-base)
	}
}

// ── EVIDENCE IS THE POINT ────────────────────────────────────────────────────────────────────────
//
// The agent cites the graph's proof rather than its own recollection, so the refs have to reach it.
func TestGraphTool_RendersEvidenceWithEveryHop(t *testing.T) {
	g := fakeGraph{hops: []GraphHop{{
		From: "secret:akia…", To: "cloud:arn:role/admin", Kind: "assumes",
		Why: "The inventory records this key as the role's.", Evidence: []string{"cloudsnap:abc123"},
	}}}
	out := callGraph(t, g, map[string]any{"op": "neighbors", "node": "secret:akia…"})
	if !strings.Contains(out, "cloudsnap:abc123") {
		t.Errorf("the hop's evidence never reached the model:\n%s", out)
	}
	if !strings.Contains(out, "assumes") {
		t.Errorf("the move kind is missing — the agent cannot tell what capability this is:\n%s", out)
	}
}

// ── THE HONESTY CASES ────────────────────────────────────────────────────────────────────────────

// A bounded search presented as complete is how an agent concludes "there is no other route" from a
// result that merely stopped early.
func TestGraphTool_TruncationIsSurfacedNotSwallowed(t *testing.T) {
	g := fakeGraph{
		paths:     []GraphPath{{Nodes: []string{"a", "b"}, Hops: []GraphHop{{From: "a", To: "b", Kind: "reaches", Evidence: []string{"f-1"}}}}},
		truncated: true,
	}
	out := callGraph(t, g, map[string]any{"op": "paths_from", "node": "a"})
	if !strings.Contains(strings.ToUpper(out), "TRUNCATED") {
		t.Errorf("a truncated search did not say so:\n%s", out)
	}
}

func TestGraphTool_CompleteResultCarriesNoTruncationWarning(t *testing.T) {
	g := fakeGraph{paths: []GraphPath{{Nodes: []string{"a", "b"}}}}
	out := callGraph(t, g, map[string]any{"op": "paths_from", "node": "a"})
	if strings.Contains(strings.ToUpper(out), "TRUNCATED") {
		t.Errorf("a complete result warned about truncation; a caveat that always fires stops being read:\n%s", out)
	}
}

// "No recorded path" and "no path exists" are different facts, and only one of them means the estate is
// safe here. An agent told the second will report an all-clear it cannot support.
func TestGraphTool_EmptyResultDoesNotReadAsClean(t *testing.T) {
	out := callGraph(t, fakeGraph{}, map[string]any{"op": "paths_from", "node": "a"})
	if !strings.Contains(strings.ToLower(out), "not proof") {
		t.Errorf("an empty traversal implied there is no path, rather than none recorded:\n%s", out)
	}
	nb := callGraph(t, fakeGraph{}, map[string]any{"op": "neighbors", "node": "a"})
	if !strings.Contains(strings.ToLower(nb), "has not been ingested") {
		t.Errorf("an isolated node was not distinguished from an un-ingested surface:\n%s", nb)
	}
}

// The anti-hallucination case: asked to justify a link that is not in the graph, the tool must tell the
// agent NOT to report it — this is the moment a chain narrative gets invented.
func TestGraphTool_UnprovenLinkTellsTheAgentNotToReportIt(t *testing.T) {
	out := callGraph(t, fakeGraph{}, map[string]any{"op": "why", "node": "a", "to": "b"})
	if !strings.Contains(strings.ToLower(out), "do not report") {
		t.Errorf("an unproven link was not refused in terms the agent can act on:\n%s", out)
	}
}

// No shared node is a real answer, not a failure. Promoting the least-unshared node to look decisive
// would be worse than saying each path is separate work.
func TestGraphTool_NoChokePointSaysSoPlainly(t *testing.T) {
	out := callGraph(t, fakeGraph{}, map[string]any{"op": "chokepoints"})
	if !strings.Contains(strings.ToLower(out), "separate work") {
		t.Errorf("an empty choke-point result was not explained:\n%s", out)
	}
}

func TestGraphTool_ChokePointsRankAndExplain(t *testing.T) {
	g := fakeGraph{cps: []GraphChokePoint{{ID: "cloud:arn:role/etl", Name: "etl", Paths: 3, Why: "Cutting this severs 3 attack paths."}}}
	out := callGraph(t, g, map[string]any{"op": "chokepoints"})
	if !strings.Contains(out, "etl") || !strings.Contains(out, "3") {
		t.Errorf("choke point not rendered usefully:\n%s", out)
	}
}

// ── ARGUMENT AND FAILURE HANDLING ────────────────────────────────────────────────────────────────

func TestGraphTool_BadArgsAreExplainedNotGuessed(t *testing.T) {
	for _, tc := range []struct {
		name, want string
		args       map[string]any
	}{
		{"missing node", "needs a node", map[string]any{"op": "neighbors"}},
		{"missing to", "needs both", map[string]any{"op": "why", "node": "a"}},
		{"unknown op", "unknown op", map[string]any{"op": "teleport", "node": "a"}},
	} {
		out := callGraph(t, fakeGraph{}, tc.args)
		if !strings.Contains(strings.ToLower(out), tc.want) {
			t.Errorf("%s: got %q, want it to mention %q", tc.name, out, tc.want)
		}
	}
}

// A traversal failure must reach the agent as a failure, not as an empty estate — otherwise a broken
// graph reads as a clean one.
func TestGraphTool_ErrorsAreReportedAsFailures(t *testing.T) {
	g := fakeGraph{err: errors.New("store unreachable")}
	for _, args := range []map[string]any{
		{"op": "neighbors", "node": "a"},
		{"op": "paths_from", "node": "a"},
		{"op": "why", "node": "a", "to": "b"},
		{"op": "chokepoints"},
	} {
		out := callGraph(t, g, args)
		if !strings.Contains(strings.ToLower(out), "failed") {
			t.Errorf("op %v hid a traversal error; a broken graph would read as a clean estate:\n%s", args["op"], out)
		}
	}
}

// ── EXACT PHASE SCOPING ──────────────────────────────────────────────────────────────────────────
//
// Phase gating is cumulative (ci >= pi), which is right for ACTING tools — once propose_fix is
// available it should stay available. The cost is structural: every phase inherits every earlier
// phase's tools, so the terminal report phase accumulates the whole catalog and is the binding
// constraint for all of it. It sat at exactly 12, meaning ANY tool added at ANY earlier phase pushed
// it over the §2.6 cap. OnlyInPhases is the opt-out for exploratory tools that have no reason to
// linger.

func TestOnlyInPhases_ExcludesLaterPhases(t *testing.T) {
	c := Catalog{{
		Schema: ToolSchema{Name: "explore"}, Phases: []Phase{PhaseInvestigate}, OnlyInPhases: true,
	}}
	in := func(p Phase) bool { return len(c.exposedIn(p)) == 1 }
	if !in(PhaseInvestigate) {
		t.Error("an exact-scoped tool is missing from its own phase")
	}
	if in(PhaseChain) || in(PhaseReport) {
		t.Error("an exact-scoped tool leaked into a later phase — the whole point is that it does not")
	}
	if in(PhaseTriage) {
		t.Error("an exact-scoped tool appeared in an earlier phase")
	}
}

// The default must be untouched, or adding this flag silently re-gates every existing tool.
func TestCumulativeGatingIsUnchangedByDefault(t *testing.T) {
	c := Catalog{{Schema: ToolSchema{Name: "act"}, Phases: []Phase{PhaseInvestigate}}}
	if len(c.exposedIn(PhaseReport)) != 1 {
		t.Error("a normal tool stopped being cumulative — every acting tool's availability just changed")
	}
	if len(c.exposedIn(PhaseTriage)) != 0 {
		t.Error("a normal tool became available before its phase")
	}
}

// An empty phase set still means every phase, so the flag alone can never hide a tool completely.
func TestOnlyInPhases_EmptySetStillMeansEveryPhase(t *testing.T) {
	c := Catalog{{Schema: ToolSchema{Name: "always"}, OnlyInPhases: true}}
	for _, p := range []Phase{PhaseTriage, PhaseInvestigate, PhaseChain, PhaseReport} {
		if len(c.exposedIn(p)) != 1 {
			t.Errorf("tool with no declared phases vanished from %s", p)
		}
	}
}
