package main

import (
	"testing"

	"github.com/ClatTribe/tsengine/internal/bench"
	"github.com/ClatTribe/tsengine/internal/cloudengine"
	"github.com/ClatTribe/tsengine/internal/cloudgraph"
	"github.com/ClatTribe/tsengine/internal/cloudquery"
)

// TestCloudDiscrimination_LargeAccountHasHeadroom is the end-to-end guarantee that the AI Cloud Engineer
// benchmark can actually TUNE an agent: on a large emulated account, the deterministic substrate at a
// bounded (realistic-scale) worklist budget MISSES real attack paths that ARE recoverable (the production
// budget finds them) — so there is genuine headroom for an agent to capture, i.e. the scenario separates a
// good agent from the substrate. A regression that made the substrate cover everything at any budget would
// silently turn the benchmark non-discriminating (an agent run would then teach nothing); this guards it.
func TestCloudDiscrimination_LargeAccountHasHeadroom(t *testing.T) {
	ds, err := cloudquery.GenerateLarge(cloudquery.SizedLargeOpts(1, 200))
	if err != nil {
		t.Fatalf("generate large account: %v", err)
	}
	findings := cloudquery.EvalProwler(ds.Tables)
	snap := cloudgraph.Ingest(cloudquery.ToInventory(ds.Tables))

	prodBudget := 8 * len(ds.AnswerKey.RealTargets)
	if prodBudget < 150 {
		prodBudget = 150
	}
	const scaleBudget = 5

	sProd := cloudquery.ScoreAssessment(ds, cloudengine.Assess(snap, findings, cloudengine.SnapshotOracle{}, cloudengine.Options{MaxHypotheses: prodBudget}))
	sScale := cloudquery.ScoreAssessment(ds, cloudengine.Assess(snap, findings, cloudengine.SnapshotOracle{}, cloudengine.Options{MaxHypotheses: scaleBudget}))

	// the production budget must reach the ceiling (every planted path is by construction reachable).
	if sProd.RealFound != sProd.RealTotal {
		t.Fatalf("production budget must reach every reachable path (the ceiling): found %d/%d", sProd.RealFound, sProd.RealTotal)
	}
	rep := bench.ComputeCloudDiscrimination("large", sProd.RealTotal, prodBudget, scaleBudget, sProd.RealFound, sScale.RealFound)

	// the bounded substrate must leave real, recoverable headroom — else the benchmark can't measure agents.
	if !rep.Discriminates() {
		t.Fatalf("a large account at a bounded budget must under-cover (leave headroom for the agent); got %d/%d at scale, headroom %d — benchmark would not discriminate agent quality",
			sScale.RealFound, sScale.RealTotal, rep.Headroom)
	}
	t.Logf("discrimination OK: ceiling %d/%d, bounded %d/%d, agent headroom %d (%.0f%%)",
		sProd.RealFound, sProd.RealTotal, sScale.RealFound, sScale.RealTotal, rep.Headroom, rep.HeadroomPct*100)
}
