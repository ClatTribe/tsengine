package estategraph

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

var (
	t0 = time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
	t1 = t0.Add(24 * time.Hour)
)

func demoEdge(p EdgeProof, refs []string, at time.Time) Edge {
	return Edge{From: "code:repo/acme", To: "cloud:role/deploy", Kind: EdgeAssumes,
		Evidence: []string{"f-1"}, Proof: p, ProofRefs: refs, ProofAt: at}
}

// A producer that predates proof state must keep claiming exactly what it claimed before — and the
// ENCODED edge must say so explicitly. An absent field is the silent-signal shape: a reader cannot
// tell "nobody attempted this" from "we forgot to record whether anyone did".
func TestEdgeWithoutProofClaimsTheWeakestThingExplicitly(t *testing.T) {
	g := New()
	if err := g.AddEdge(Edge{From: "a", To: "b", Kind: EdgeReaches, Evidence: []string{"f-1"}}); err != nil {
		t.Fatalf("AddEdge: %v", err)
	}
	got := g.Edges[0]
	if got.Proof != ProofConfigPossible {
		t.Errorf("default proof = %q, want %q", got.Proof, ProofConfigPossible)
	}
	b, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(b), `"proof":"config_possible"`) {
		t.Errorf("encoded edge must carry an EXPLICIT proof state, got %s", b)
	}
}

// An evidenced proof cites a replayable attempt and says when. Both refusals are load-bearing: without
// refs the graph launders an inference as a proof; without a stamp no reader can age it and no merge
// can order it against a contradicting attempt.
func TestEvidencedProofNeedsAReplayableDatedAttempt(t *testing.T) {
	for _, tc := range []struct {
		name string
		edge Edge
		want error
	}{
		{"demonstrated without refs", demoEdge(ProofDemonstrated, nil, t0), ErrProofUngrounded},
		{"demonstrated without stamp", demoEdge(ProofDemonstrated, []string{"demo-7"}, time.Time{}), ErrProofUnstamped},
		{"exploit_failed without refs", demoEdge(ProofExploitFailed, nil, t0), ErrProofUngrounded},
		{"exploit_failed without stamp", demoEdge(ProofExploitFailed, []string{"demo-7"}, time.Time{}), ErrProofUnstamped},
		{"empty refs are not refs", demoEdge(ProofDemonstrated, []string{"", "  "}, t0), ErrProofUngrounded},
		{"a state nobody defined", demoEdge("probably_exploitable", []string{"demo-7"}, t0), ErrUnknownProof},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g := New()
			err := g.AddEdge(tc.edge)
			if !errors.Is(err, tc.want) {
				t.Fatalf("AddEdge err = %v, want %v", err, tc.want)
			}
			if len(g.Edges) != 0 {
				t.Errorf("a refused edge must not land in the graph, got %d", len(g.Edges))
			}
		})
	}

	g := New()
	if err := g.AddEdge(demoEdge(ProofDemonstrated, []string{"demo-7"}, t0)); err != nil {
		t.Fatalf("a grounded, dated demonstration must be accepted: %v", err)
	}
}

// The merge rule is TIME, not severity. A rank in either direction is a bug: rank demonstrated highest
// and a fix can never be recorded; rank exploit_failed highest and a stale failure tells a customer a
// live path is dead.
func TestMergeProofIsDecidedByTimeNotSeverity(t *testing.T) {
	for _, tc := range []struct {
		name             string
		cur              EdgeProof
		curAt            time.Time
		in               EdgeProof
		inAt             time.Time
		want             EdgeProof
		wantAt           time.Time
		whyItWouldBeABug string
	}{
		{"config re-assert never erases a demonstration", ProofDemonstrated, t0, ProofConfigPossible, t1, ProofDemonstrated, t0,
			"re-ingesting an inventory would silently delete the strongest fact the product produces"},
		{"a demonstration upgrades config-possible", ProofConfigPossible, time.Time{}, ProofDemonstrated, t0, ProofDemonstrated, t0, ""},
		{"a NEWER failure downgrades a demonstration", ProofDemonstrated, t0, ProofExploitFailed, t1, ProofExploitFailed, t1,
			"a fix that landed would never register, and the proof would outlive the thing that made it true"},
		{"an OLDER failure does NOT erase a newer demonstration", ProofDemonstrated, t1, ProofExploitFailed, t0, ProofDemonstrated, t1,
			"a stale re-attack would report a live path as dead"},
		{"the zero value is config-possible", "", time.Time{}, ProofDemonstrated, t0, ProofDemonstrated, t0, ""},
		{"on an exact tie the weaker claim wins", ProofDemonstrated, t0, ProofExploitFailed, t0, ProofExploitFailed, t0,
			"identical evidence must not be resolved toward asserting exploitability"},
		{"config over config stays config", ProofConfigPossible, time.Time{}, ProofConfigPossible, t0, ProofConfigPossible, time.Time{}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, at := MergeProof(tc.cur, tc.curAt, tc.in, tc.inAt)
			if got != tc.want || !at.Equal(tc.wantAt) {
				t.Errorf("MergeProof(%q@%v, %q@%v) = %q@%v, want %q@%v\n%s",
					tc.cur, tc.curAt, tc.in, tc.inAt, got, at, tc.want, tc.wantAt, tc.whyItWouldBeABug)
			}
		})
	}
}

// The same rules must hold through AddEdge's merge-into-an-existing-move path, and the refs must follow
// the claim that SURVIVED — an edge citing an attempt that no longer backs what it says is worse than
// one citing nothing.
func TestReassertingAnEdgeCannotEraseItsProof(t *testing.T) {
	g := New()
	if err := g.AddEdge(demoEdge(ProofDemonstrated, []string{"demo-7"}, t0)); err != nil {
		t.Fatalf("seed: %v", err)
	}
	// An inventory re-ingest: same hop, config-possible, no attempt behind it.
	if err := g.AddEdge(Edge{From: "code:repo/acme", To: "cloud:role/deploy", Kind: EdgeAssumes,
		Evidence: []string{"f-2"}}); err != nil {
		t.Fatalf("re-assert: %v", err)
	}
	if len(g.Edges) != 1 {
		t.Fatalf("the same move must merge, got %d edges", len(g.Edges))
	}
	if got := g.Edges[0]; got.Proof != ProofDemonstrated || !got.ProofAt.Equal(t0) {
		t.Errorf("a config re-assert erased a demonstration: %q@%v", got.Proof, got.ProofAt)
	}
	if len(g.Edges[0].Evidence) != 2 {
		t.Errorf("evidence should still union across surfaces, got %v", g.Edges[0].Evidence)
	}

	// A later failed re-attack: the claim flips and the refs become the failure's.
	if err := g.AddEdge(demoEdge(ProofExploitFailed, []string{"reattack-9"}, t1)); err != nil {
		t.Fatalf("downgrade: %v", err)
	}
	got := g.Edges[0]
	if got.Proof != ProofExploitFailed || !got.ProofAt.Equal(t1) {
		t.Fatalf("evidenced downgrade did not apply: %q@%v", got.Proof, got.ProofAt)
	}
	if len(got.ProofRefs) != 1 || got.ProofRefs[0] != "reattack-9" {
		t.Errorf("refs must follow the surviving claim, got %v", got.ProofRefs)
	}
}

// A path is proven only if every hop is. The second refusal is the subtle one: a path carrying an
// untested hop must NOT report exploit_failed, because on a PATH that reads as "we ran this route and
// it stopped working" — which implies it once worked end to end.
func TestPathProofIsTheWeakestHop(t *testing.T) {
	hop := func(p EdgeProof) Edge { return Edge{From: "a", To: "b", Kind: EdgeReaches, Proof: p} }
	for _, tc := range []struct {
		name string
		path Path
		want EdgeProof
	}{
		{"no hops proves nothing", Path{}, ProofConfigPossible},
		{"every hop demonstrated", Path{Edges: []Edge{hop(ProofDemonstrated), hop(ProofDemonstrated)}}, ProofDemonstrated},
		{"one untested hop", Path{Edges: []Edge{hop(ProofDemonstrated), hop(ProofConfigPossible)}}, ProofConfigPossible},
		{"zero-value hop counts as untested", Path{Edges: []Edge{hop(ProofDemonstrated), hop("")}}, ProofConfigPossible},
		{"fully evidenced, one hop now failing", Path{Edges: []Edge{hop(ProofDemonstrated), hop(ProofExploitFailed)}}, ProofExploitFailed},
		// BOTH ORDERS. The first version of this table tested only one, and a mutation that returned
		// exploit_failed whenever any hop had failed passed it — the weakest hop must win regardless of
		// where it sits in the path, and a table that walks one direction cannot see that.
		{"untested hop before a failing one stays untested", Path{Edges: []Edge{hop(ProofConfigPossible), hop(ProofExploitFailed)}}, ProofConfigPossible},
		{"untested hop AFTER a failing one stays untested", Path{Edges: []Edge{hop(ProofExploitFailed), hop(ProofConfigPossible)}}, ProofConfigPossible},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.path.Proof(); got != tc.want {
				t.Errorf("Path.Proof() = %q, want %q", got, tc.want)
			}
		})
	}
}

// Merge folds another surface's subgraph in by calling AddEdge, so the proof refusals apply there too.
// Asserted rather than assumed: a source graph whose edges were appended directly (never validated) is
// exactly how an ungrounded proof would get smuggled past the front door.
func TestMergeIsNotABackDoorForAnUngroundedProof(t *testing.T) {
	other := New()
	other.Edges = append(other.Edges,
		Edge{From: "a", To: "b", Kind: EdgeReaches, Evidence: []string{"f-1"}, Proof: ProofDemonstrated}, // no refs, no stamp
		Edge{From: "a", To: "c", Kind: EdgeReaches, Evidence: []string{"f-2"}, Proof: ProofDemonstrated, ProofRefs: []string{"demo-1"}, ProofAt: t0},
	)

	g := New()
	g.Merge(other)

	if len(g.Edges) != 1 {
		t.Fatalf("want only the grounded edge merged, got %d", len(g.Edges))
	}
	if g.Edges[0].To != "c" {
		t.Errorf("the ungrounded proof was smuggled in: %+v", g.Edges[0])
	}
}
