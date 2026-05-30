package cloudengine

import (
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/internal/cloudgraph"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// scenario: internet → alb → ec2 → web-role → assume → data-role → reads PII.
func handBuilt() *cloudgraph.Snapshot {
	s := cloudgraph.New("acct", "aws")
	s.AddNode(&cloudgraph.Node{ID: cloudgraph.InternetID, Kind: cloudgraph.KindNetwork})
	s.AddNode(&cloudgraph.Node{ID: "alb", Kind: cloudgraph.KindResource, Public: true, Name: "alb"})
	s.AddNode(&cloudgraph.Node{ID: "ec2", Kind: cloudgraph.KindResource, Name: "ec2"})
	s.AddNode(&cloudgraph.Node{ID: "web", Kind: cloudgraph.KindPrincipal, Name: "web-role"})
	s.AddNode(&cloudgraph.Node{ID: "data", Kind: cloudgraph.KindPrincipal, Name: "data-role"})
	s.AddNode(&cloudgraph.Node{ID: "pii", Kind: cloudgraph.KindData, Sensitive: cloudgraph.SensHigh, Name: "pii-bucket"})
	s.AddEdge(cloudgraph.Edge{From: cloudgraph.InternetID, To: "alb", Kind: cloudgraph.EdgeNetworkReach})
	s.AddEdge(cloudgraph.Edge{From: "alb", To: "ec2", Kind: cloudgraph.EdgeNetworkReach})
	s.AddEdge(cloudgraph.Edge{From: "ec2", To: "web", Kind: cloudgraph.EdgeRunsAs})
	s.AddEdge(cloudgraph.Edge{From: "web", To: "data", Kind: cloudgraph.EdgeAssumeRole})
	s.AddEdge(cloudgraph.Edge{From: "data", To: "pii", Kind: cloudgraph.EdgeHasAccess})
	return s
}

func TestAssess_FindsPathWithEvidenceAndRemediation(t *testing.T) {
	snap := handBuilt()
	prowler := []types.Finding{{ID: "p-1", Tool: "prowler", Endpoint: "AWS::IAM::Role data @us-east-1"}}
	a := Assess(snap, prowler, SnapshotOracle{}, Options{})

	if len(a.Paths) != 1 {
		t.Fatalf("want 1 attack path, got %d", len(a.Paths))
	}
	p := a.Paths[0]
	if !p.RealImpact.LiveReachable || p.RealImpact.Score < 0.99 {
		t.Errorf("PII path should be reachable + high-impact: %+v", p.RealImpact)
	}
	if len(p.Evidence) == 0 {
		t.Error("finding must carry an evidence bundle")
	}
	if p.Remediation == "" {
		t.Error("finding must carry remediation (cheapest edge to cut)")
	}
	if !strings.Contains(p.Narrative, "assumes") {
		t.Errorf("narrative should describe the assume-role move: %q", p.Narrative)
	}
	if a.SnapshotHash == "" {
		t.Error("assessment must pin the snapshot hash")
	}
	// the prowler finding on data-role sits on the real path → corroborated
	if len(p.Corroborates) != 1 || p.Corroborates[0] != "p-1" {
		t.Errorf("prowler p-1 on the path should be corroborated: %v", p.Corroborates)
	}
}

func TestAssess_DowngradesBlockedDecoy(t *testing.T) {
	snap := handBuilt()
	// block the assume edge ⇒ the PII path is config-possible but not reachable.
	oracle := SnapshotOracle{Blocked: map[string]bool{"web->data:assume_role": true}}
	prowler := []types.Finding{{ID: "p-1", Tool: "prowler", Endpoint: "AWS::S3::Bucket pii @us-east-1"}}
	a := Assess(snap, prowler, oracle, Options{})

	if len(a.Paths) != 0 {
		t.Fatalf("blocked path must NOT become a finding, got %d", len(a.Paths))
	}
	if len(a.Downgraded) != 1 || a.Downgraded[0] != "p-1" {
		t.Errorf("the inert prowler finding should be downgraded: %v", a.Downgraded)
	}
}

func TestSynthetic_GenerateVerifyAssessScore(t *testing.T) {
	for _, seed := range []int64{1, 2, 42, 1000} {
		scn := Generate(seed, 3, 2, true) // includes the IAM privesc-to-admin chain
		if err := scn.Verify(); err != nil {
			t.Fatalf("seed %d: scenario failed deterministic verify: %v", seed, err)
		}
		a := Assess(scn.Snapshot, scn.Prowler, scn.Oracle(), Options{})
		s := ScoreEngine(scn, a)
		if !s.Pass {
			t.Errorf("seed %d: engine should ace a verified scenario: %+v", seed, s)
		}
		if s.PathRecall != 1.0 {
			t.Errorf("seed %d: path recall %.2f, want 1.0", seed, s.PathRecall)
		}
		if s.FPReduction != 1.0 {
			t.Errorf("seed %d: FP-reduction %.2f, want 1.0 (decoys downgraded)", seed, s.FPReduction)
		}
		if s.FalsePaths != 0 {
			t.Errorf("seed %d: %d false paths", seed, s.FalsePaths)
		}
	}
}

func TestSynthetic_ScalesToManyRealPaths(t *testing.T) {
	// A dense account: 25 planted network→data chains + an IAM privesc chain per
	// scenario (26 real paths each). With a raised worklist budget the engineer
	// must find every one and still downgrade all decoys — proving the engine
	// scales past the default governor when given the budget.
	const nReal, nDecoy = 25, 3
	agg, n, err := RunSynthetic(11, 20, nReal, nDecoy, true, 60)
	if err != nil {
		t.Fatalf("scaled synthetic run errored: %v", err)
	}
	if !agg.Pass {
		t.Errorf("engine must ace 26-real-path scenarios at budget 60: %+v", agg)
	}
	if agg.PathRecall != 1.0 {
		t.Errorf("path recall %.4f over %d scenarios, want 1.0 (%d/%d)",
			agg.PathRecall, n, agg.RealFound, agg.RealTotal)
	}
	if agg.FPReduction != 1.0 {
		t.Errorf("FP-reduction %.4f, want 1.0 (%d/%d decoys)", agg.FPReduction, agg.DecoyDowngraded, agg.DecoyTotal)
	}
	if agg.FalsePaths != 0 {
		t.Errorf("%d false paths at scale", agg.FalsePaths)
	}

	// And the governor is real: at the default budget (20) the same dense
	// scenarios can't validate all 26 real paths, so recall is bounded below 1.0.
	// This documents that --max-hypotheses is the load-bearing knob.
	capped, _, err := RunSynthetic(11, 5, nReal, nDecoy, true, 0)
	if err != nil {
		t.Fatalf("default-budget run errored: %v", err)
	}
	if capped.PathRecall >= 1.0 {
		t.Errorf("default worklist budget should cap recall below 1.0 on dense scenarios, got %.4f", capped.PathRecall)
	}
}

func TestSynthetic_VerifierRejectsBadScenario(t *testing.T) {
	scn := Generate(7, 2, 1, false)
	// Corrupt the scenario so a "decoy" becomes genuinely reachable. A decoy is
	// inert via TWO independent mechanisms now: the live oracle's Blocked map AND
	// the snapshot Condition on its assume edge (a conditioned edge is not
	// passively confirmable — config-possible ≠ exploitable, ADR 0002). To make
	// it a real path we must defeat both: clear the block AND strip the runtime
	// condition. With both gone the decoy is reachable → Verify must reject it.
	scn.Blocked = map[string]bool{}
	for i := range scn.Snapshot.Edges {
		scn.Snapshot.Edges[i].Condition = ""
	}
	if err := scn.Verify(); err == nil {
		t.Error("verifier must reject a scenario whose decoy is actually reachable")
	}
}

func TestSynthetic_PrivescChainDetected(t *testing.T) {
	// A privesc-only scenario: the engine must discover the IAM
	// escalation-to-admin chain via the cloudiam evaluator + bridge.
	scn := Generate(99, 0, 0, true)
	if err := scn.Verify(); err != nil {
		t.Fatalf("privesc scenario failed verify: %v", err)
	}
	a := Assess(scn.Snapshot, scn.Prowler, scn.Oracle(), Options{})
	if s := ScoreEngine(scn, a); !s.Pass || s.PathRecall != 1.0 {
		t.Fatalf("engine must detect the privesc-to-admin chain: %+v", s)
	}
	// the discovered path should end at the synthetic admin node
	found := false
	for _, p := range a.Paths {
		if pathEnd(p) == "admin" {
			found = true
		}
	}
	if !found {
		t.Error("a path to the effective-admin node should be reported")
	}
}
