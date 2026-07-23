package cloudagent

import (
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/internal/cloudgraph"
)

// TestResolve_ConditionalEdgeNotDroppedAsNo is the regression for the reachability under-report:
// the agent's reachableFrom traversed only UNCONDITIONAL edges, so a conditional-but-real path (an
// edge the engine keeps pending live confirmation, §10) read as "NO — likely inert" — a false
// negative, the dangerous direction for a defensive engineer. resolve_access must instead report it
// as reachable-but-conditional, matching the engine's keep-on-uncertainty semantics.
func TestResolve_ConditionalEdgeNotDroppedAsNo(t *testing.T) {
	s := cloudgraph.New("acct", "aws")
	s.AddNode(&cloudgraph.Node{ID: "attacker", Kind: cloudgraph.KindPrincipal})
	s.AddNode(&cloudgraph.Node{ID: "pii", Kind: cloudgraph.KindData, Sensitive: cloudgraph.SensHigh})
	// the ONLY path attacker→pii is gated by an unresolved runtime condition.
	s.AddEdge(cloudgraph.Edge{From: "attacker", To: "pii", Kind: cloudgraph.EdgeHasAccess, Condition: "aws:MultiFactorAuthPresent"})

	cc := &Context{Snap: s}
	out := tResolve(cc, map[string]any{"principal": "attacker", "resource": "pii"})
	if strings.HasPrefix(out, "NO") {
		t.Fatalf("a conditional-but-real path must NOT read as NO/inert: %q", out)
	}
	if !strings.Contains(out, "CONDITIONAL") {
		t.Errorf("conditional reachability must be flagged as such (not a bare YES): %q", out)
	}
}

// TestResolve_UnconditionalStaysDefinite: an unconditional path still returns the plain definite YES
// (the fix must not turn every reachable node conditional).
func TestResolve_UnconditionalStaysDefinite(t *testing.T) {
	s := cloudgraph.New("acct", "aws")
	s.AddNode(&cloudgraph.Node{ID: "attacker", Kind: cloudgraph.KindPrincipal})
	s.AddNode(&cloudgraph.Node{ID: "pii", Kind: cloudgraph.KindData, Sensitive: cloudgraph.SensHigh})
	s.AddEdge(cloudgraph.Edge{From: "attacker", To: "pii", Kind: cloudgraph.EdgeHasAccess})

	out := tResolve(&Context{Snap: s}, map[string]any{"principal": "attacker", "resource": "pii"})
	if !strings.HasPrefix(out, "YES") || strings.Contains(out, "CONDITIONAL") {
		t.Errorf("an unconditional path must be a plain definite YES: %q", out)
	}
}

// TestResolve_TrulyUnreachableStillNo: a node with no path at all still reads NO — the fix widens to
// conditional edges, it does not invent reachability.
func TestResolve_TrulyUnreachableStillNo(t *testing.T) {
	s := cloudgraph.New("acct", "aws")
	s.AddNode(&cloudgraph.Node{ID: "attacker", Kind: cloudgraph.KindPrincipal})
	s.AddNode(&cloudgraph.Node{ID: "pii", Kind: cloudgraph.KindData, Sensitive: cloudgraph.SensHigh})
	// no edge between them
	out := tResolve(&Context{Snap: s}, map[string]any{"principal": "attacker", "resource": "pii"})
	if !strings.HasPrefix(out, "NO") {
		t.Errorf("a genuinely unreachable resource must still read NO: %q", out)
	}
}

// TestBlast_ConditionalJewelCountedAndFlagged: a crown jewel reachable only via a conditional edge is
// now counted in the blast radius (previously invisible) AND tagged conditional.
func TestBlast_ConditionalJewelCountedAndFlagged(t *testing.T) {
	s := cloudgraph.New("acct", "aws")
	s.AddNode(&cloudgraph.Node{ID: "attacker", Kind: cloudgraph.KindPrincipal})
	s.AddNode(&cloudgraph.Node{ID: "admin", Kind: cloudgraph.KindPrincipal, Privileged: true})
	s.AddEdge(cloudgraph.Edge{From: "attacker", To: "admin", Kind: cloudgraph.EdgePrivesc, Condition: "aws:MultiFactorAuthPresent"})

	out := tBlast(&Context{Snap: s}, map[string]any{"principal": "attacker"})
	if !strings.Contains(out, "admin") {
		t.Fatalf("a conditionally-reachable crown jewel must be counted in the blast radius: %q", out)
	}
	if !strings.Contains(out, "conditional") {
		t.Errorf("a conditionally-reachable jewel must be tagged conditional: %q", out)
	}
}
