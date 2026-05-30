package cloudengine

import (
	"fmt"
	"strings"

	"github.com/ClatTribe/tsengine/pkg/types"
)

// EngineScore is the AI Cloud Engineer scorecard for one scenario (docs/design
// §6). The two headline metrics: attack-path recall (did it find the planted
// real paths) and FP-reduction (did it downgrade the config-bad-but-inert
// decoys — the differentiator vs a config linter). FalsePaths guards against
// reporting paths that aren't real.
type EngineScore struct {
	RealTotal       int     `json:"real_total"`
	RealFound       int     `json:"real_found"`
	PathRecall      float64 `json:"path_recall"`
	DecoyTotal      int     `json:"decoy_total"`
	DecoyDowngraded int     `json:"decoy_downgraded"`
	FPReduction     float64 `json:"fp_reduction"`
	FalsePaths      int     `json:"false_paths"` // reported paths not ending at a real target
	Pass            bool    `json:"pass"`
}

// ScoreEngine compares the engine's assessment against the scenario's verified
// labels. SUT-agnostic: it reads the labels from the scenario data, not from any
// hardcoded resource identifier.
func ScoreEngine(scn *Scenario, a *types.AIAssessment) EngineScore {
	real := map[string]bool{}
	for _, t := range scn.RealTargets {
		real[t] = true
	}
	found := map[string]bool{}
	falsePaths := 0
	for _, p := range a.Paths {
		end := pathEnd(p)
		if real[end] {
			found[end] = true
		} else {
			falsePaths++
		}
	}
	downgraded := map[string]bool{}
	for _, d := range a.Downgraded {
		downgraded[d] = true
	}
	decoyDown := 0
	for _, fid := range scn.DecoyFindings {
		if downgraded[fid] {
			decoyDown++
		}
	}

	s := EngineScore{
		RealTotal: len(scn.RealTargets), RealFound: len(found),
		DecoyTotal: len(scn.DecoyFindings), DecoyDowngraded: decoyDown,
		FalsePaths: falsePaths,
	}
	s.PathRecall = ratio(s.RealFound, s.RealTotal)
	s.FPReduction = ratio(s.DecoyDowngraded, s.DecoyTotal)
	s.Pass = s.RealFound == s.RealTotal && s.DecoyDowngraded == s.DecoyTotal && s.FalsePaths == 0
	return s
}

// RunSynthetic generates → verifies → assesses → scores n scenarios and returns
// the aggregate scorecard. Every scenario must pass the deterministic Verify()
// before it is scored (the anti-circularity safeguard).
func RunSynthetic(seedBase int64, n, nReal, nDecoy int) (EngineScore, int, error) {
	agg := EngineScore{Pass: true}
	for i := 0; i < n; i++ {
		scn := Generate(seedBase+int64(i), nReal, nDecoy)
		if err := scn.Verify(); err != nil {
			return agg, i, fmt.Errorf("scenario %d failed verify: %w", i, err)
		}
		a := Assess(scn.Snapshot, scn.Prowler, scn.Oracle(), Options{})
		s := ScoreEngine(scn, a)
		agg.RealTotal += s.RealTotal
		agg.RealFound += s.RealFound
		agg.DecoyTotal += s.DecoyTotal
		agg.DecoyDowngraded += s.DecoyDowngraded
		agg.FalsePaths += s.FalsePaths
		if !s.Pass {
			agg.Pass = false
		}
	}
	agg.PathRecall = ratio(agg.RealFound, agg.RealTotal)
	agg.FPReduction = ratio(agg.DecoyDowngraded, agg.DecoyTotal)
	return agg, n, nil
}

func pathEnd(p types.AttackPath) string {
	if n := len(p.Graph.Nodes); n > 0 {
		return p.Graph.Nodes[n-1].ID
	}
	return ""
}

func ratio(num, den int) float64 {
	if den == 0 {
		return 1
	}
	return float64(num) / float64(den)
}

// RenderEngineScore formats an aggregate scorecard with the mandatory baseline
// cite (the dual-view delta vs prowler — §14.2).
func RenderEngineScore(agg EngineScore, scenarios int) string {
	var b strings.Builder
	verdict := "PASS"
	if !agg.Pass {
		verdict = "FAIL"
	}
	fmt.Fprintf(&b, "=== AI Cloud Engineer scorecard (%d scenarios) ===\n", scenarios)
	fmt.Fprintf(&b, "attack-path recall: %.2f%%  (%d/%d planted paths found)\n",
		agg.PathRecall*100, agg.RealFound, agg.RealTotal)
	fmt.Fprintf(&b, "FP-reduction:       %.2f%%  (%d/%d decoys downgraded)\n",
		agg.FPReduction*100, agg.DecoyDowngraded, agg.DecoyTotal)
	fmt.Fprintf(&b, "false paths:        %d\n", agg.FalsePaths)
	fmt.Fprintf(&b, "verdict:            %s\n", verdict)
	fmt.Fprintf(&b, "baseline: prowler-alone flags every decoy as a finding and never chains the\n")
	fmt.Fprintf(&b, "  real paths; the engineer's value is the delta — finding the chains AND\n")
	fmt.Fprintf(&b, "  downgrading the %d inert decoys (CLAUDE.md §14, dual-view ablation).\n", agg.DecoyTotal)
	return b.String()
}
