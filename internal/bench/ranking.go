package bench

import (
	"fmt"
	"math"
	"strings"
)

// ranking.go — triage / PRIORITIZATION accuracy for the L2 agent.
//
// Recall/precision score the SET an agent flags; RANKING scores the ORDER. This matters because the L2
// Lead's core job (§2.2 "prioritized findings") is triage: a human works the list top-down, so an agent
// that surfaces the right items but ranks its FALSE flags above the real ones fails triage even at 100%
// recall. Set-metrics can't see that; a ranking metric can. This closes an L2-evaluation completeness gap:
// the benchmark measured WHAT the agent flagged, not the ORDER it presented them in.
//
// Binary relevance (an item is truly high-impact or not), two standard measures:
//   PrecisionAtK — K = the number of truly-relevant items among those ranked; of the top-K the agent
//     ranked, the fraction that are truly relevant. 1.0 = every real item is ranked above every false one.
//   NDCG — position-discounted gain (relevance / log2(rank+1)) over the ideal ordering. 1.0 = the real
//     items occupy the top positions; it degrades smoothly as they sink beneath noise.

// RankedItem is one item in the agent's prioritized output, with its ground-truth relevance label.
type RankedItem struct {
	ID         string `json:"id"`
	HighImpact bool   `json:"high_impact"` // the GROUND-TRUTH label (not the agent's claim)
}

// RankingScore grades the order of a prioritized list.
type RankingScore struct {
	Total        int     `json:"total"`          // items ranked
	Relevant     int     `json:"relevant"`       // truly high-impact among them
	PrecisionAtK float64 `json:"precision_at_k"` // K = Relevant
	NDCG         float64 `json:"ndcg"`
}

// ComputeRankingScore grades a prioritized list (best-first) by binary relevance.
func ComputeRankingScore(ranked []RankedItem) RankingScore {
	s := RankingScore{Total: len(ranked)}
	for _, it := range ranked {
		if it.HighImpact {
			s.Relevant++
		}
	}
	if s.Relevant == 0 {
		// nothing relevant was ranked — order is vacuously perfect (there's nothing to mis-order).
		s.PrecisionAtK, s.NDCG = 1, 1
		return s
	}
	// precision@K, K = the number of relevant items: of the top-K positions, how many are relevant.
	topRel := 0
	for i := 0; i < s.Relevant && i < len(ranked); i++ {
		if ranked[i].HighImpact {
			topRel++
		}
	}
	s.PrecisionAtK = float64(topRel) / float64(s.Relevant)
	// NDCG with binary gains.
	dcg := 0.0
	for i, it := range ranked {
		if it.HighImpact {
			dcg += 1.0 / math.Log2(float64(i)+2)
		}
	}
	idcg := 0.0
	for i := 0; i < s.Relevant; i++ {
		idcg += 1.0 / math.Log2(float64(i)+2)
	}
	if idcg > 0 {
		s.NDCG = dcg / idcg
	}
	return s
}

// GoodTriage reports whether the agent ranked every real item above every false one (perfect top-K).
func (s RankingScore) GoodTriage() bool { return s.PrecisionAtK >= 1.0 }

// RenderRankingScore is the one-line triage read.
func RenderRankingScore(s RankingScore) string {
	var b strings.Builder
	fmt.Fprintf(&b, "triage/ranking: precision@%d %.0f%%, NDCG %.2f — %s\n",
		s.Relevant, s.PrecisionAtK*100, s.NDCG,
		map[bool]string{true: "impactful items ranked above the noise", false: "false flags buried real items (triage miss)"}[s.GoodTriage()])
	return b.String()
}
