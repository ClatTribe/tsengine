package codereviewbench

import (
	"math"
	"strings"
	"testing"
)

func cqCorpus() []Case {
	return []Case{
		{ID: "A", Repo: "o/a", Golden: []Range{{"src/a.ts", 10, 12}}, PublishedAt: "2026-09-01"},
		{ID: "B", Repo: "o/b", Golden: []Range{{"pkg/b.go", 50, 50}}, PublishedAt: "2026-09-02"},
	}
}

// A frontier arm that finds both at a real cost, a free local arm that finds one, and an arm whose
// cost is unknown. The table must price the first two per correct finding and withhold the third.
func TestAggregate_CostPerCorrectAndSpread(t *testing.T) {
	cases := cqCorpus()
	// frontier: repeat 1 finds A+B, repeat 2 finds only A → spread; cost known $4 total each run.
	frontier := Arm{Label: "frontier", Runs: []Predictions{
		{Tool: "codesweep", Model: "gpt-x", CostUSD: 4, CostKnown: true,
			Ran:   map[string]bool{"A": true, "B": true},
			Cases: map[string][]Prediction{"A": {{File: "src/a.ts", Line: 11}}, "B": {{File: "pkg/b.go", Line: 50}}}},
		{Tool: "codesweep", Model: "gpt-x", CostUSD: 4, CostKnown: true,
			Ran:   map[string]bool{"A": true, "B": true},
			Cases: map[string][]Prediction{"A": {{File: "src/a.ts", Line: 11}}}},
	}}
	local := Arm{Label: "qwen (local)", Runs: []Predictions{
		{Tool: "codesweep", Model: "qwen3:8b", CostUSD: 0, CostKnown: true,
			Ran:   map[string]bool{"A": true, "B": true},
			Cases: map[string][]Prediction{"A": {{File: "src/a.ts", Line: 11}}}},
	}}
	unknown := Arm{Label: "mystery", Runs: []Predictions{
		{Tool: "codesweep", Model: "m", CostKnown: false,
			Ran:   map[string]bool{"A": true, "B": true},
			Cases: map[string][]Prediction{"A": {{File: "src/a.ts", Line: 11}}}},
	}}

	cmp, err := Aggregate(cases, []Arm{frontier, local, unknown}, DefaultTolerance, "2026-08-01")
	if err != nil {
		t.Fatal(err)
	}
	by := map[string]ArmResult{}
	for _, a := range cmp.Arms {
		by[a.Label] = a
	}
	f := by["frontier"]
	// recall strict: repeat1 = 2/2, repeat2 = 1/2 → mean 0.75, min 0.5 max 1.0
	if math.Abs(f.RecallStrictMean-0.75) > 1e-9 || f.RecallStrictMin != 0.5 || f.RecallStrictMax != 1.0 {
		t.Fatalf("frontier recall spread wrong: %+v", f)
	}
	// 3 correct finds total over $8 total → $2.67
	if f.CostPerCorrectUSD == nil || math.Abs(*f.CostPerCorrectUSD-8.0/3.0) > 1e-6 {
		t.Fatalf("frontier cost-per-correct wrong: %v", f.CostPerCorrectUSD)
	}
	l := by["qwen (local)"]
	// A free arm is marked self-hosted; the per-correct pointer stays nil and the render shows $0 from
	// the flag, so a bare $0 is never confused with "priced at zero".
	if !l.SelfHosted || l.CostPerCorrectUSD != nil {
		t.Fatalf("a free arm must read self-hosted, cost-per-correct unset: %+v", l)
	}
	if !strings.Contains(RenderComparison(Comparison{Arms: []ArmResult{l}, Cases: 2}), "$0") {
		t.Fatal("a self-hosted arm must render $0")
	}
	u := by["mystery"]
	if u.CostKnown || u.CostPerCorrectUSD != nil {
		t.Fatalf("an unknown-cost arm must withhold cost per correct (unknown != free): %+v", u)
	}
	if cmp.AfterCutoff != 2 {
		t.Fatalf("after-cutoff count: %d", cmp.AfterCutoff)
	}
}

// Two different models under one arm label is two arms, not repeats — averaging them is the "17 vs 15"
// conflation and must be refused.
func TestAggregate_RefusesMixedConfigUnderOneLabel(t *testing.T) {
	cases := cqCorpus()
	bad := Arm{Label: "x", Runs: []Predictions{
		{Tool: "codesweep", Model: "a", Ran: map[string]bool{}},
		{Tool: "codesweep", Model: "b", Ran: map[string]bool{}},
	}}
	if _, err := Aggregate(cases, []Arm{bad}, DefaultTolerance, ""); err == nil {
		t.Fatal("mixing two models under one label must be rejected")
	}
}

func TestRenderComparison_OrdersByRecallAndStatesHeldOut(t *testing.T) {
	cases := cqCorpus()
	cmp, _ := Aggregate(cases, []Arm{
		{Label: "weak", Runs: []Predictions{{Tool: "codesweep", Model: "w", CostKnown: true, Ran: map[string]bool{"A": true, "B": true}}}},
		{Label: "strong", Runs: []Predictions{{Tool: "codesweep", Model: "s", CostUSD: 2, CostKnown: true,
			Ran: map[string]bool{"A": true, "B": true}, Cases: map[string][]Prediction{"A": {{File: "src/a.ts", Line: 11}}, "B": {{File: "pkg/b.go", Line: 50}}}}}},
	}, DefaultTolerance, "")
	out := RenderComparison(cmp)
	if strings.Index(out, "strong") > strings.Index(out, "weak") {
		t.Error("the table must order by recall, best first")
	}
	for _, must := range []string{"Held-out status", "no longer held out", "cost per correct", "Shown a fixed file", "Spread matters"} {
		if !strings.Contains(out, must) {
			t.Errorf("report missing %q", must)
		}
	}
}
