package bench

import (
	"math"
	"testing"
)

func approxEq(a, b float64) bool { return math.Abs(a-b) < 1e-9 }

func TestRankingScore(t *testing.T) {
	// perfect triage: the 3 real items ranked above the 2 false flags.
	perfect := ComputeRankingScore([]RankedItem{
		{"a", true}, {"b", true}, {"c", true}, {"d", false}, {"e", false},
	})
	if !perfect.GoodTriage() || !approxEq(perfect.PrecisionAtK, 1) || !approxEq(perfect.NDCG, 1) {
		t.Errorf("real items ranked first is perfect triage, got %+v", perfect)
	}

	// bad triage: a false flag ranked FIRST, real items beneath it.
	bad := ComputeRankingScore([]RankedItem{
		{"d", false}, {"a", true}, {"b", true}, {"c", true},
	})
	if bad.GoodTriage() {
		t.Error("a false flag ranked above real items is NOT good triage")
	}
	// K=3 (3 relevant); top-3 are {false,true,true} → 2/3.
	if !approxEq(bad.PrecisionAtK, 2.0/3.0) {
		t.Errorf("precision@3 should be 2/3, got %v", bad.PrecisionAtK)
	}
	// NDCG < 1 because the relevant items are discounted below their ideal positions.
	if bad.NDCG >= 1 || bad.NDCG <= 0 {
		t.Errorf("NDCG should be in (0,1) for a mis-ordered list, got %v", bad.NDCG)
	}

	// no relevant items ranked → vacuously perfect (nothing to mis-order).
	none := ComputeRankingScore([]RankedItem{{"x", false}, {"y", false}})
	if !none.GoodTriage() || none.Relevant != 0 {
		t.Errorf("a list with no relevant items is vacuously good, got %+v", none)
	}

	// a strictly worse order has a strictly lower NDCG than a better one (monotonicity sanity).
	better := ComputeRankingScore([]RankedItem{{"a", true}, {"d", false}, {"b", true}})
	worse := ComputeRankingScore([]RankedItem{{"d", false}, {"a", true}, {"b", true}})
	if !(better.NDCG > worse.NDCG) {
		t.Errorf("ranking a real item higher must raise NDCG: better %v vs worse %v", better.NDCG, worse.NDCG)
	}
}
