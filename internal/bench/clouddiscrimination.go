package bench

import (
	"fmt"
	"sort"
	"strings"
)

// clouddiscrimination.go — the DISCRIMINATION metric for the AI Cloud/Security Engineer benchmark.
//
// A benchmark can only TUNE an agent if it separates a good agent from the deterministic substrate. On a
// clean scenario the substrate already finds every attack path (recall 100%), so it gives the agent NO
// headroom — the run can't tell a great engineer from a mediocre one, and spending LLM budget on it teaches
// nothing. Measured this directly: on the seeded synthetic account both the substrate AND a frontier agent
// scored 100%/100% — a non-discriminating scenario.
//
// Discrimination quantifies the headroom that makes agent quality MEASURABLE. Run the engine at a
// PRODUCTION budget (a generous worklist — every planted path is by-construction reachable, so this is the
// reachable CEILING) and at a realistic-SCALE budget (a bounded worklist — at enterprise scale you cannot
// exhaustively enumerate every path). The gap is the real-but-missed paths a good agent's TARGETED tool-use
// (find_paths / blast_radius on the right nodes) could still recover — the agent's opportunity. A scenario
// with Headroom>0 measures agent quality; Headroom==0 means the substrate carries it and the run is silent
// about the agent.
//
// Deterministic + LLM-free: this establishes a scenario's discriminating power BEFORE any LLM budget is
// spent, so a tuning campaign can select only scenarios that actually separate agents (§14 anti-overfit —
// don't tune against a benchmark that can't distinguish).

// CloudDiscriminationReport is the headroom a scenario gives an agent over the bounded substrate.
type CloudDiscriminationReport struct {
	Account          string  `json:"account,omitempty"`
	RealTargets      int     `json:"real_targets"`
	ProductionBudget int     `json:"production_budget"` // generous worklist — the reachable ceiling
	ScaleBudget      int     `json:"scale_budget"`      // bounded worklist — realistic enterprise scale
	FoundProduction  int     `json:"found_production"`  // real paths the engine covers at the production budget
	FoundScale       int     `json:"found_scale"`       // real paths the engine covers at the scale budget
	Headroom         int     `json:"headroom"`          // FoundProduction-FoundScale: missed-but-recoverable = the agent's room
	HeadroomPct      float64 `json:"headroom_pct"`      // headroom as a fraction of the reachable set
}

// ComputeCloudDiscrimination derives the report from the two budget runs' found-counts. foundProduction is
// the reachable ceiling (a generous budget); foundScale is the bounded run. Headroom is what the bounded
// substrate misses yet is provably recoverable (the production run reached it) — the agent's measurable room.
func ComputeCloudDiscrimination(account string, realTargets, prodBudget, scaleBudget, foundProduction, foundScale int) CloudDiscriminationReport {
	if foundScale > foundProduction {
		foundScale = foundProduction // the bounded run can't beat the ceiling (guard a noisy input)
	}
	head := foundProduction - foundScale
	r := CloudDiscriminationReport{
		Account: account, RealTargets: realTargets,
		ProductionBudget: prodBudget, ScaleBudget: scaleBudget,
		FoundProduction: foundProduction, FoundScale: foundScale, Headroom: head,
	}
	if foundProduction > 0 {
		r.HeadroomPct = float64(head) / float64(foundProduction)
	}
	return r
}

// Discriminates reports whether this scenario can measure agent quality: the bounded substrate leaves real,
// recoverable paths on the table for the agent to find. Headroom==0 → the substrate carries it and an agent
// run tells you nothing (a non-discriminating scenario — don't spend LLM budget tuning against it).
func (r CloudDiscriminationReport) Discriminates() bool { return r.Headroom > 0 }

// RenderCloudDiscrimination is the operator-facing report.
func RenderCloudDiscrimination(r CloudDiscriminationReport) string {
	var b strings.Builder
	fmt.Fprintf(&b, "=== Benchmark discrimination — the AGENT's measurable headroom ===\n")
	if r.Account != "" {
		fmt.Fprintf(&b, "account: %s\n", r.Account)
	}
	fmt.Fprintf(&b, "reachable attack paths (ground truth): %d\n", r.RealTargets)
	fmt.Fprintf(&b, "substrate @ production budget (%d): found %d/%d (the reachable ceiling)\n",
		r.ProductionBudget, r.FoundProduction, r.RealTargets)
	fmt.Fprintf(&b, "substrate @ realistic-scale budget (%d): found %d/%d (bounded — can't exhaustively enumerate)\n",
		r.ScaleBudget, r.FoundScale, r.RealTargets)
	fmt.Fprintf(&b, "AGENT HEADROOM: %d path(s) (%.1f%%) — real, recoverable, missed by the bounded substrate\n",
		r.Headroom, r.HeadroomPct*100)
	if r.Discriminates() {
		fmt.Fprintf(&b, "verdict: DISCRIMINATES — an agent run on this scenario measures real quality (capture of the headroom).\n")
	} else {
		fmt.Fprintf(&b, "verdict: does NOT discriminate — the substrate covers everything; an agent run here teaches nothing (don't spend LLM budget).\n")
	}
	return b.String()
}

// DiscriminationSweep aggregates the discrimination report across many seeded scenarios — the curated
// tuning corpus. It answers "which scenarios give the agent MEASURABLE headroom", so a tuning campaign
// spends (expensive) LLM budget only where the run can teach something: a scenario the substrate fully
// covers is worthless for tuning (the agent can't out-do a substrate that already found everything).
type DiscriminationSweep struct {
	Total          int                         `json:"total"`
	Discriminating int                         `json:"discriminating"` // scenarios with headroom > 0
	TotalHeadroom  int                         `json:"total_headroom"`
	MinHeadroom    int                         `json:"min_headroom"`
	MedianHeadroom int                         `json:"median_headroom"`
	MaxHeadroom    int                         `json:"max_headroom"`
	Reports        []CloudDiscriminationReport `json:"reports,omitempty"`
}

// DiscriminatingFraction is the share of swept scenarios that measure agent quality.
func (s DiscriminationSweep) DiscriminatingFraction() float64 {
	if s.Total == 0 {
		return 0
	}
	return float64(s.Discriminating) / float64(s.Total)
}

// AggregateDiscrimination rolls a set of per-scenario reports into the sweep summary.
func AggregateDiscrimination(reports []CloudDiscriminationReport) DiscriminationSweep {
	sw := DiscriminationSweep{Total: len(reports), Reports: reports}
	heads := make([]int, 0, len(reports))
	for _, r := range reports {
		if r.Discriminates() {
			sw.Discriminating++
		}
		sw.TotalHeadroom += r.Headroom
		heads = append(heads, r.Headroom)
	}
	if len(heads) > 0 {
		sort.Ints(heads)
		sw.MinHeadroom = heads[0]
		sw.MaxHeadroom = heads[len(heads)-1]
		sw.MedianHeadroom = heads[len(heads)/2]
	}
	return sw
}

// RenderDiscriminationSweep is the operator-facing corpus summary — how many scenarios are worth an agent
// run, and the headroom distribution across them.
func RenderDiscriminationSweep(s DiscriminationSweep) string {
	var b strings.Builder
	fmt.Fprintf(&b, "=== Discrimination sweep — the tuning corpus (%d scenarios) ===\n", s.Total)
	fmt.Fprintf(&b, "discriminating: %d/%d (%.0f%%) — scenarios where an agent run measures real quality\n",
		s.Discriminating, s.Total, s.DiscriminatingFraction()*100)
	fmt.Fprintf(&b, "headroom (real, recoverable paths the bounded substrate misses): min %d, median %d, max %d\n",
		s.MinHeadroom, s.MedianHeadroom, s.MaxHeadroom)
	if s.Discriminating == 0 {
		fmt.Fprintf(&b, "verdict: NO scenario discriminates at this budget — tighten --max-hypotheses or grow the accounts before spending LLM budget.\n")
	} else {
		fmt.Fprintf(&b, "verdict: run the agent head-to-head on the %d discriminating scenario(s) to measure its lift.\n", s.Discriminating)
	}
	return b.String()
}
