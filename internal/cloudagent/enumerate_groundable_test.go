package cloudagent

import (
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/internal/cloudgraph"
)

// TestEnumerateSeedIsRecordable is the contract between the two halves of the documented
// flow: enumerate_attack_paths SEEDS the investigation, record_issue COMMITS it. The seed is
// only a seed if the path it prints is the path record_issue accepts.
//
// It was not. tEnumerate printed the prose narrative (display names: "i-1024") while
// validatePath grounds against graph node IDs ("arn:aws:ec2:...:instance/pub-1023"), so an
// agent that followed the prompt's own "good flow" got REJECTED on its first record and had
// to re-derive every path via find_paths. Observed live on a frontier-model run.
//
// This asserts the rendered "path (record_issue format)" chain validates for EVERY candidate
// the prepass emits — mutation-proof: revert tEnumerate to narrative-only and the parse finds
// no chain, so the test fails rather than silently passing.
func TestEnumerateSeedIsRecordable(t *testing.T) {
	snap := groundableFixture()
	cc := &Context{Snap: snap, MaxHyp: 20}

	out := tEnumerate(cc, nil)
	if strings.Contains(out, "found no real-impact attack paths") {
		t.Fatalf("fixture produced no candidate paths — the test cannot check the contract:\n%s", out)
	}

	const marker = "path (record_issue format): "
	var chains [][]string
	for _, line := range strings.Split(out, "\n") {
		i := strings.Index(line, marker)
		if i < 0 {
			continue
		}
		parts := strings.Split(strings.TrimSpace(line[i+len(marker):]), " -> ")
		for j := range parts {
			parts[j] = strings.TrimSpace(parts[j])
		}
		chains = append(chains, parts)
	}
	if len(chains) == 0 {
		t.Fatalf("enumerate_attack_paths printed NO record_issue-format path — an agent following the\ndocumented enumerate->record flow cannot ground its first claim. Output:\n%s", out)
	}

	for _, chain := range chains {
		target := chain[len(chain)-1]
		if err := validatePath(snap, chain, target); err != nil {
			t.Errorf("the prepass seeded a path record_issue rejects: %v\n  chain: %s", err, strings.Join(chain, " -> "))
		}
	}
}

// groundableFixture builds the canonical shape the benchmark accounts use: an
// internet-reachable public instance running a role that reads a crown-jewel bucket.
func groundableFixture() *cloudgraph.Snapshot {
	snap := cloudgraph.New("test-account", "aws")
	inst := "arn:aws:ec2:us-east-1:123456789012:instance/pub-1"
	role := "arn:aws:iam::123456789012:role/reader-1"
	data := "arn:aws:s3:::crownjewel-1"

	snap.AddNode(&cloudgraph.Node{ID: inst, Kind: cloudgraph.KindResource, Type: "aws_instance", Public: true})
	snap.AddNode(&cloudgraph.Node{ID: role, Kind: cloudgraph.KindPrincipal, Type: "aws_iam_role"})
	snap.AddNode(&cloudgraph.Node{ID: data, Kind: cloudgraph.KindData, Type: "aws_s3_bucket", Sensitive: cloudgraph.SensHigh})

	snap.AddEdge(cloudgraph.Edge{From: cloudgraph.InternetID, To: inst, Kind: cloudgraph.EdgeNetworkReach})
	snap.AddEdge(cloudgraph.Edge{From: inst, To: role, Kind: cloudgraph.EdgeRunsAs})
	snap.AddEdge(cloudgraph.Edge{From: role, To: data, Kind: cloudgraph.EdgeHasAccess})
	return snap
}

// TestEnumerateDisclosesUnexaminedJewels is the coverage half of the seed contract (§5.2 inv. 5
// with the AGENT as the reader). The prepass truncates candidates at MaxHypotheses, but rendered
// its output as if it were the account's complete attack-path set — so a crown jewel it never
// examined read identically to one it had cleared, and the agent stopped at the seed. Measured
// live: 5 seeded paths, 6 further reachable jewels never mentioned, agent recall stuck at 5/11.
//
// The disclosure must name what was NOT examined (never where a path is — that would be an answer
// key), and must stay SILENT on a complete pass, or it becomes noise.
func TestEnumerateDisclosesUnexaminedJewels(t *testing.T) {
	snap := groundableFixture()
	// A second crown jewel the bounded prepass will not reach within a cap of 1.
	other := "arn:aws:s3:::crownjewel-2"
	inst2 := "arn:aws:ec2:us-east-1:123456789012:instance/pub-2"
	role2 := "arn:aws:iam::123456789012:role/reader-2"
	snap.AddNode(&cloudgraph.Node{ID: inst2, Kind: cloudgraph.KindResource, Type: "aws_instance", Public: true})
	snap.AddNode(&cloudgraph.Node{ID: role2, Kind: cloudgraph.KindPrincipal, Type: "aws_iam_role"})
	snap.AddNode(&cloudgraph.Node{ID: other, Kind: cloudgraph.KindData, Type: "aws_s3_bucket", Sensitive: cloudgraph.SensHigh})
	snap.AddEdge(cloudgraph.Edge{From: cloudgraph.InternetID, To: inst2, Kind: cloudgraph.EdgeNetworkReach})
	snap.AddEdge(cloudgraph.Edge{From: inst2, To: role2, Kind: cloudgraph.EdgeRunsAs})
	snap.AddEdge(cloudgraph.Edge{From: role2, To: other, Kind: cloudgraph.EdgeHasAccess})

	// Bounded run: the cap forces at least one jewel to go unexamined.
	bounded := tEnumerate(&Context{Snap: snap, MaxHyp: 1}, nil)
	if !strings.Contains(bounded, "COVERAGE:") {
		t.Errorf("a BOUNDED prepass disclosed no coverage gap — an unexamined jewel reads as a cleared one:\n%s", bounded)
	}
	if !strings.Contains(bounded, "not examined") {
		t.Errorf("the disclosure must say the jewels were NOT EXAMINED (not that they are safe):\n%s", bounded)
	}
	// It must name an unexamined jewel so the agent can act on it.
	if !strings.Contains(bounded, "crownjewel-1") && !strings.Contains(bounded, "crownjewel-2") {
		t.Errorf("the disclosure names no unexamined crown jewel, so it is not actionable:\n%s", bounded)
	}

	// Complete run: every jewel reached → the disclosure must be SILENT.
	complete := tEnumerate(&Context{Snap: snap, MaxHyp: 20}, nil)
	if strings.Contains(complete, "COVERAGE:") {
		t.Errorf("a COMPLETE prepass declared a coverage gap it does not have — noise the agent learns to ignore:\n%s", complete)
	}
}
