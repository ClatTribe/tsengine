package webagent

import (
	"fmt"
	"strings"
)

// Render formats the agent's engagement report.
func Render(r *Report) string {
	var b strings.Builder
	b.WriteString("=== AI Web/API Penetration Tester (LLM agent) — engagement ===\n")
	fmt.Fprintf(&b, "target: %s\n", r.Target)
	if r.Summary != "" {
		fmt.Fprintf(&b, "summary: %s\n", r.Summary)
	}
	fmt.Fprintf(&b, "proved %d finding(s) over %d tool call(s), %d request(s) sent\n",
		len(r.Findings), r.Calls, r.Requests)
	for _, f := range r.Findings {
		tick := " "
		if f.Verified {
			tick = "✓"
		}
		fmt.Fprintf(&b, "\n[%s] %s  class=%s  severity=%s  verified=%s\n", f.ID, f.Route, f.Class, f.Severity, tick)
		if f.Rationale != "" {
			fmt.Fprintf(&b, "  why: %s\n", f.Rationale)
		}
		if len(f.Evidence) > 0 {
			fmt.Fprintf(&b, "  evidence turns: %s\n", strings.Join(f.Evidence, ", "))
		}
	}
	return b.String()
}

// Score measures recorded findings against a set of known-vulnerable routes (the
// test fixture's answer key) — recall + invented-finding count. Grounding already
// guarantees every recorded finding is structurally backed by an indicator; this
// measures whether the agent found the right routes and invented none.
type Score struct {
	RealTotal int      `json:"real_total"`
	RealFound int      `json:"real_found"`
	Recall    float64  `json:"recall"`
	Invented  int      `json:"invented"` // findings on routes NOT in the answer key
	Missed    []string `json:"missed,omitempty"`
	Pass      bool     `json:"pass"`
}

// ScoreAgainst compares findings to known-vulnerable routes (by class:route key).
func (r *Report) ScoreAgainst(realRoutes map[string]string) Score {
	// realRoutes: route -> expected class.
	found := map[string]bool{}
	var s Score
	for _, f := range r.Findings {
		if cls, ok := realRoutes[f.Route]; ok && cls == f.Class {
			found[f.Route] = true
		} else {
			s.Invented++
		}
	}
	for route := range realRoutes {
		s.RealTotal++
		if found[route] {
			s.RealFound++
		} else {
			s.Missed = append(s.Missed, route)
		}
	}
	if s.RealTotal > 0 {
		s.Recall = float64(s.RealFound) / float64(s.RealTotal)
	} else {
		s.Recall = 1
	}
	s.Pass = s.RealFound == s.RealTotal && s.Invented == 0
	return s
}
