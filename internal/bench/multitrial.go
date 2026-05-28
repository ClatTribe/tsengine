package bench

import (
	"math"
	"sort"
)

// TrialStats summarizes a metric over N trials. Single-trial bench
// numbers are noise (CLAUDE.md §14.2.3), so the harness reports median
// + p10/p90 across repeated runs.
type TrialStats struct {
	N      int     `json:"n"`
	Median float64 `json:"median"`
	P10    float64 `json:"p10"`
	P90    float64 `json:"p90"`
	Min    float64 `json:"min"`
	Max    float64 `json:"max"`
}

// stats computes median + p10/p90 over the given samples.
func stats(samples []float64) TrialStats {
	if len(samples) == 0 {
		return TrialStats{}
	}
	sorted := append([]float64(nil), samples...)
	sort.Float64s(sorted)
	return TrialStats{
		N:      len(sorted),
		Median: percentile(sorted, 50),
		P10:    percentile(sorted, 10),
		P90:    percentile(sorted, 90),
		Min:    sorted[0],
		Max:    sorted[len(sorted)-1],
	}
}

// percentile uses linear interpolation on a pre-sorted slice.
func percentile(sorted []float64, p float64) float64 {
	if len(sorted) == 1 {
		return sorted[0]
	}
	rank := (p / 100) * float64(len(sorted)-1)
	lo := int(math.Floor(rank))
	hi := int(math.Ceil(rank))
	if lo == hi {
		return sorted[lo]
	}
	frac := rank - float64(lo)
	return sorted[lo]*(1-frac) + sorted[hi]*frac
}
