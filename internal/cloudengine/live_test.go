package cloudengine

import (
	"testing"

	"github.com/ClatTribe/tsengine/internal/cloudgraph"
	"github.com/ClatTribe/tsengine/internal/cloudsafety"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// mockAnalyzer returns canned results; reachKO / permKO / probeKO force a
// specific check to fail.
type mockAnalyzer struct {
	reachKO, permKO, probeKO bool
}

func (m mockAnalyzer) Reachable(_, _ string) (bool, error)  { return !m.reachKO, nil }
func (m mockAnalyzer) PermActive(_, _ string) (bool, error) { return !m.permKO, nil }
func (m mockAnalyzer) Probe(_, _ string) (bool, error)      { return !m.probeKO, nil }

func livePath() cloudgraph.Path {
	return cloudgraph.Path{
		Nodes: []string{cloudgraph.InternetID, "alb", "ec2", "web", "data", "pii"},
		Edges: []cloudgraph.Edge{
			{From: cloudgraph.InternetID, To: "alb", Kind: cloudgraph.EdgeNetworkReach},
			{From: "alb", To: "ec2", Kind: cloudgraph.EdgeNetworkReach},
			{From: "ec2", To: "web", Kind: cloudgraph.EdgeRunsAs},
			{From: "web", To: "data", Kind: cloudgraph.EdgeAssumeRole},
			{From: "data", To: "pii", Kind: cloudgraph.EdgeHasAccess},
		},
	}
}

func TestLiveValidator_ConfirmsReachablePath(t *testing.T) {
	g := cloudsafety.NewGuard(50)
	lv := NewLiveValidator(mockAnalyzer{}, g)
	ok, rung, ev := lv.Validate(livePath())
	if !ok {
		t.Fatal("all-green analyzer should confirm the path reachable")
	}
	if rung < 3 {
		t.Errorf("network edges should reach rung 3, got %d", rung)
	}
	if len(ev) == 0 {
		t.Error("validation must record evidence")
	}
	// every guarded call must have been read-only (no ErrMutating in the log).
	for _, c := range g.Log() {
		if !cloudsafety.ReadOnly(c.Action) {
			t.Errorf("live validator issued a non-read-only action: %s", c.Action)
		}
	}
}

func TestLiveValidator_KillsUnreachablePath(t *testing.T) {
	g := cloudsafety.NewGuard(50)
	lv := NewLiveValidator(mockAnalyzer{reachKO: true}, g)
	if ok, _, _ := lv.Validate(livePath()); ok {
		t.Error("a path whose network edge isn't reachable must be killed")
	}
}

func TestLiveValidator_BudgetEnforced(t *testing.T) {
	g := cloudsafety.NewGuard(1) // only one live call allowed
	lv := NewLiveValidator(mockAnalyzer{}, g)
	ok, _, _ := lv.Validate(livePath())
	if ok {
		t.Error("path should fail closed once the live-call budget is exhausted")
	}
	if g.Used() != 1 {
		t.Errorf("guard should have spent exactly its budget of 1, used %d", g.Used())
	}
}

func TestLiveValidator_ConditionedEdgeQueuesHumanGate(t *testing.T) {
	g := cloudsafety.NewGuard(50)
	lv := NewLiveValidator(mockAnalyzer{}, g)
	lv.MaxRung = 3 // below the rung-4 probe needed to confirm a condition
	p := livePath()
	p.Edges[3].Condition = "aws:MultiFactorAuthPresent=true" // the assume edge is conditioned
	ok, _, ev := lv.Validate(p)
	if ok {
		t.Error("a conditioned edge needing rung-4 must not auto-confirm when capped at rung 3")
	}
	if len(lv.Pending) != 1 {
		t.Errorf("the path should be queued for human rung-5 approval, pending=%v", lv.Pending)
	}
	if !hasRung5Evidence(ev) {
		t.Error("evidence should record the queued rung-5 step")
	}
}

func hasRung5Evidence(ev []types.EvidenceItem) bool {
	for _, e := range ev {
		if e.AtRung == 5 {
			return true
		}
	}
	return false
}
