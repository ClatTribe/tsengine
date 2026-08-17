package bench

import (
	"fmt"
	"sort"
	"strings"
)

// SCuBAProductScore is the per-baseline (per M365/GWS product) breakdown.
type SCuBAProductScore struct {
	Product    string
	Detectable int
	Full       int // detectable policies with at least one non-partial rule
	Partial    int // detectable policies covered ONLY by partial rules
}

// SCuBAScore is the scored SCuBA catalog. The denominator is stated three ways on
// purpose: Total is the whole published baseline, Detectable is the honest
// scanner-addressable subset, and Shall isolates the mandatory half. A single
// blended percentage would hide which one a claim rests on.
type SCuBAScore struct {
	Total      int
	Detectable int
	Procedural int
	Federal    int

	Full    int // detectable + at least one full rule
	Partial int // detectable + partial rules only

	DetectableShall int
	FullShall       int

	ByProduct []SCuBAProductScore
	// Gaps are detectable policies with NO mapped rule, SHALL first — the
	// improvement-loop worklist, not a footnote.
	Gaps []SCuBAPolicy
	// Rules is every distinct tsengine rule id the mapping claims (partial marker
	// stripped). scuba_test.go asserts each one is really emitted by an assessor.
	Rules []string
}

// ScoreSCuBA scores the catalog. Pure; no I/O.
func ScoreSCuBA(cat []SCuBAPolicy) SCuBAScore {
	var s SCuBAScore
	byProd := map[string]*SCuBAProductScore{}
	seenRule := map[string]bool{}
	order := []string{}

	for _, p := range cat {
		s.Total++
		switch p.Scope {
		case ScopeProcedural:
			s.Procedural++
		case ScopeFederal:
			s.Federal++
		}
		for _, r := range p.Rules {
			id := strings.TrimPrefix(r, "~")
			if id != "" && !seenRule[id] {
				seenRule[id] = true
				s.Rules = append(s.Rules, id)
			}
		}
		if p.Scope != ScopeDetectable {
			continue
		}
		s.Detectable++
		ps := byProd[p.Product]
		if ps == nil {
			ps = &SCuBAProductScore{Product: p.Product}
			byProd[p.Product] = ps
			order = append(order, p.Product)
		}
		ps.Detectable++
		if p.Shall {
			s.DetectableShall++
		}
		switch {
		case !p.Covered():
			s.Gaps = append(s.Gaps, p)
		case p.Partial():
			s.Partial++
			ps.Partial++
		default:
			s.Full++
			ps.Full++
			if p.Shall {
				s.FullShall++
			}
		}
	}

	sort.Strings(s.Rules)
	sort.SliceStable(s.Gaps, func(i, j int) bool {
		if s.Gaps[i].Shall != s.Gaps[j].Shall {
			return s.Gaps[i].Shall // mandatory gaps first
		}
		return s.Gaps[i].ID < s.Gaps[j].ID
	})
	for _, k := range order {
		s.ByProduct = append(s.ByProduct, *byProd[k])
	}
	return s
}

// Recall is full-coverage over the detectable denominator. Partial coverage is
// deliberately NOT counted — a weaker adjacent check is not the policy.
func (s SCuBAScore) Recall() float64 {
	if s.Detectable == 0 {
		return 0
	}
	return float64(s.Full) / float64(s.Detectable)
}

// ShallRecall is the same over the mandatory (SHALL) subset — the number that
// matters most, since SHOULD policies are advisory even for CISA.
func (s SCuBAScore) ShallRecall() float64 {
	if s.DetectableShall == 0 {
		return 0
	}
	return float64(s.FullShall) / float64(s.DetectableShall)
}

// RenderSCuBAReport renders the scorecard. States the neutral source and both
// denominators; never prints a compliance verdict (§10 / grc.Coverage discipline).
func RenderSCuBAReport(s SCuBAScore, maxGaps int) string {
	var b strings.Builder
	b.WriteString("# SCuBA identity/SaaS posture benchmark (neutral)\n\n")
	b.WriteString("Source: CISA Secure Cloud Business Applications baselines — ")
	b.WriteString("cisagov/ScubaGear (M365) + cisagov/ScubaGoggles (Google Workspace), CC0.\n")
	b.WriteString("Measures tsengine DETECTION RECALL against an external control set. ")
	b.WriteString("Not a SCuBA compliance claim.\n\n")
	fmt.Fprintf(&b, "- published policies: **%d**\n", s.Total)
	fmt.Fprintf(&b, "- scanner-detectable: **%d** (excluded: %d procedural, %d federal-specific)\n",
		s.Detectable, s.Procedural, s.Federal)
	fmt.Fprintf(&b, "- detected in full: **%d** → recall **%.3f**\n", s.Full, s.Recall())
	fmt.Fprintf(&b, "- mandatory (SHALL) recall: **%.3f** (%d/%d)\n", s.ShallRecall(), s.FullShall, s.DetectableShall)
	fmt.Fprintf(&b, "- partial only (adjacent/weaker check): %d\n", s.Partial)
	fmt.Fprintf(&b, "- tsengine rules exercised: %d\n\n", len(s.Rules))

	b.WriteString("| Baseline | Detectable | Full | Partial | Recall |\n|---|---|---|---|---|\n")
	for _, p := range s.ByProduct {
		r := 0.0
		if p.Detectable > 0 {
			r = float64(p.Full) / float64(p.Detectable)
		}
		fmt.Fprintf(&b, "| %s | %d | %d | %d | %.3f |\n", p.Product, p.Detectable, p.Full, p.Partial, r)
	}

	if len(s.Gaps) > 0 {
		fmt.Fprintf(&b, "\n## Uncovered detectable policies (%d) — the improvement worklist\n\n", len(s.Gaps))
		n := len(s.Gaps)
		if maxGaps > 0 && maxGaps < n {
			n = maxGaps
		}
		for _, g := range s.Gaps[:n] {
			lvl := "SHOULD"
			if g.Shall {
				lvl = "SHALL"
			}
			fmt.Fprintf(&b, "- `%s` (%s, %s) — %s\n", g.ID, g.Product, lvl, g.Requirement)
		}
		if n < len(s.Gaps) {
			fmt.Fprintf(&b, "- …and %d more\n", len(s.Gaps)-n)
		}
	}
	return b.String()
}
