package cloudagent

import (
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/internal/cloudgraph"
)

// coverageFixture: two reachable crown jewels, plus one DECOY jewel with no path.
func coverageFixture() *cloudgraph.Snapshot {
	snap := cloudgraph.New("test-account", "aws")
	for _, n := range []struct{ inst, role, data string }{
		{"arn:aws:ec2:us-east-1:123456789012:instance/pub-1", "arn:aws:iam::123456789012:role/reader-1", "arn:aws:s3:::crownjewel-1"},
		{"arn:aws:ec2:us-east-1:123456789012:instance/pub-2", "arn:aws:iam::123456789012:role/reader-2", "arn:aws:s3:::crownjewel-2"},
	} {
		snap.AddNode(&cloudgraph.Node{ID: n.inst, Kind: cloudgraph.KindResource, Type: "aws_instance", Public: true})
		snap.AddNode(&cloudgraph.Node{ID: n.role, Kind: cloudgraph.KindPrincipal, Type: "aws_iam_role"})
		snap.AddNode(&cloudgraph.Node{ID: n.data, Kind: cloudgraph.KindData, Type: "aws_s3_bucket", Sensitive: cloudgraph.SensHigh})
		snap.AddEdge(cloudgraph.Edge{From: cloudgraph.InternetID, To: n.inst, Kind: cloudgraph.EdgeNetworkReach})
		snap.AddEdge(cloudgraph.Edge{From: n.inst, To: n.role, Kind: cloudgraph.EdgeRunsAs})
		snap.AddEdge(cloudgraph.Edge{From: n.role, To: n.data, Kind: cloudgraph.EdgeHasAccess})
	}
	// A decoy jewel: sensitive but no path reaches it.
	snap.AddNode(&cloudgraph.Node{ID: "arn:aws:s3:::decoy-isolated-1", Kind: cloudgraph.KindData, Type: "aws_s3_bucket", Sensitive: cloudgraph.SensHigh})
	return snap
}

func recorded(cc *Context, target string) {
	cc.Issues = append(cc.Issues, Issue{ID: "ai-x", Target: target, FixKind: "iam_policy"})
}

// TestCoverageGateHoldsThenClosesOnEarlyQuit reproduces the seed-3 failure: the agent recorded one
// jewel and tried to finish while a second reachable jewel sat unexamined. The gate must hold ONCE
// (naming the missed jewel), then close on the next finish — never trap.
func TestCoverageGateHoldsThenClosesOnEarlyQuit(t *testing.T) {
	cc := &Context{Snap: coverageFixture()}
	recorded(cc, "arn:aws:s3:::crownjewel-1") // examined + recorded #1; never looked at #2

	first := tFinish(cc, map[string]any{"summary": "done early"})
	if cc.Done {
		t.Fatal("finish closed with a reachable, unexamined jewel — the seed-3 early-quit passes through")
	}
	if !strings.Contains(first, "crownjewel-2") {
		t.Errorf("the hold must NAME the missed jewel, got: %s", first)
	}
	if strings.Contains(first, "->") || strings.Contains(first, "pub-2") {
		t.Errorf("the gate leaked a PATH, not just the jewel id — that would be an answer key: %s", first)
	}

	second := tFinish(cc, map[string]any{"summary": "closing anyway"})
	if !cc.Done {
		t.Fatal("second finish did not close — a jewel the model won't examine would trap it forever")
	}
	if cc.Summary != "closing anyway" {
		t.Errorf("closing summary dropped: %q", cc.Summary)
	}
	_ = second
}

// TestCoverageGateIgnoresDecoysAndExaminedJewels is the anti-false-fire guard, and the reason the
// gate needs the `queried` set and the path check. A jewel the agent LOOKED at (find_paths) and a
// DECOY with no path must both be invisible to the gate — otherwise it fires on every clean run and
// the agent learns to ignore it (or gets trapped).
func TestCoverageGateIgnoresDecoysAndExaminedJewels(t *testing.T) {
	cc := &Context{Snap: coverageFixture()}
	recorded(cc, "arn:aws:s3:::crownjewel-1")
	// The agent looked at #2 via find_paths (say it declined to record — irrelevant) ...
	tFindPaths(cc, map[string]any{"target": "arn:aws:s3:::crownjewel-2"})
	// ... and looked at the decoy too.
	tFindPaths(cc, map[string]any{"target": "arn:aws:s3:::decoy-isolated-1"})

	if got := uncoveredJewels(cc); len(got) != 0 {
		t.Errorf("every reachable jewel was examined and the decoy has no path, so nothing is uncovered — got %v", got)
	}
	if out := tFinish(cc, map[string]any{"summary": "clean"}); !cc.Done {
		t.Errorf("finish was held on an account with no reachable-unexamined jewel — a false fire: %s", out)
	}
}

// TestCoverageGateNeverFiresWhenDecoyIsTheOnlyGap pins the path check specifically: even with NO
// find_paths calls, a decoy (no path) must not hold finish, because you cannot record a path that
// does not exist.
func TestCoverageGateNeverFiresWhenDecoyIsTheOnlyGap(t *testing.T) {
	cc := &Context{Snap: coverageFixture()}
	recorded(cc, "arn:aws:s3:::crownjewel-1")
	recorded(cc, "arn:aws:s3:::crownjewel-2") // both reachable jewels recorded; only the decoy remains
	if got := uncoveredJewels(cc); len(got) != 0 {
		t.Errorf("only the pathless decoy remains, which is not coverable — got %v", got)
	}
}
