package cloudagent

import (
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/internal/cloudgraph"
)

// TestRecordIssueTracksRemainingCoverage covers the state-tracking half (S-component). The prepass
// discloses what it did not examine ONCE, at turn one. By the time the agent has worked through a
// few jewels that snapshot is stale, and it is carrying the rest of the checklist in its head —
// which is where it stops early (measured: 7/11 and 10/11 after acting on the one-shot disclosure).
//
// So record_issue restates what is LEFT, and must COUNT DOWN as jewels are closed out — a counter
// that does not move is the stale snapshot again, wearing a fresh label. It must also go silent
// once nothing is left, or the agent is told there is more to do when there is not.
func TestRecordIssueTracksRemainingCoverage(t *testing.T) {
	snap := twoJewelFixture()
	cc := &Context{Snap: snap, MaxHyp: 20}

	first := tRecord(cc, map[string]any{
		"target":   "arn:aws:s3:::crownjewel-1",
		"path":     []any{cloudgraph.InternetID, "arn:aws:ec2:us-east-1:123456789012:instance/pub-1", "arn:aws:iam::123456789012:role/reader-1", "arn:aws:s3:::crownjewel-1"},
		"severity": "high",
	})
	if !strings.Contains(first, "recorded ai-001") {
		t.Fatalf("setup failed — the first record was not accepted: %s", first)
	}
	if !strings.Contains(first, "REMAINING") || !strings.Contains(first, "crownjewel-2") {
		t.Errorf("after closing one jewel the agent was not told the OTHER is still unexamined: %s", first)
	}

	second := tRecord(cc, map[string]any{
		"target":   "arn:aws:s3:::crownjewel-2",
		"path":     []any{cloudgraph.InternetID, "arn:aws:ec2:us-east-1:123456789012:instance/pub-2", "arn:aws:iam::123456789012:role/reader-2", "arn:aws:s3:::crownjewel-2"},
		"severity": "high",
	})
	if !strings.Contains(second, "recorded ai-002") {
		t.Fatalf("setup failed — the second record was not accepted: %s", second)
	}
	// The countdown is the whole point: with every jewel recorded there is nothing left to say.
	if strings.Contains(second, "REMAINING") {
		t.Errorf("every jewel is now recorded, but the agent was still told work remains — a counter\nthat does not move is the stale snapshot again: %s", second)
	}
}

func twoJewelFixture() *cloudgraph.Snapshot {
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
	return snap
}

// TestCoverageDisclosureIsNotAnAnswerKey is the anti-overfit guard for the coverage work
// (fixes #2/#4). The disclosure tells the agent which crown jewels nobody has examined — and the
// benchmark accounts deliberately label DECOY jewels that no path reaches. If the disclosure
// listed only the reachable ones it would be an answer key: the agent could record every named
// jewel without grounding anything, and recall would rise for a reason that does not generalise.
//
// So an UNREACHABLE jewel must appear in the disclosure exactly like a reachable one. The agent
// still has to call find_paths and ground each; a decoy simply yields nothing to record. (Live
// runs corroborate this: invented stayed 0 while recall rose.)
func TestCoverageDisclosureIsNotAnAnswerKey(t *testing.T) {
	snap := twoJewelFixture()
	// An isolated crown jewel: sensitive, but nothing reaches it — the decoy shape.
	decoy := "arn:aws:s3:::decoy-isolated-1"
	snap.AddNode(&cloudgraph.Node{ID: decoy, Kind: cloudgraph.KindData, Type: "aws_s3_bucket", Sensitive: cloudgraph.SensHigh})

	left := unexaminedJewels(&Context{Snap: snap}, nil)
	var sawDecoy, sawReal bool
	for _, id := range left {
		if id == decoy {
			sawDecoy = true
		}
		if id == "arn:aws:s3:::crownjewel-1" {
			sawReal = true
		}
	}
	if !sawReal {
		t.Fatal("setup failed — a reachable jewel was not listed as unexamined")
	}
	if !sawDecoy {
		t.Error("the disclosure omitted an UNREACHABLE crown jewel, so it is filtered to the reachable\n" +
			"set — that is an answer key, not a coverage statement. It must name what nobody examined,\n" +
			"and let the agent discover (via find_paths) that a decoy has no path.")
	}
}
