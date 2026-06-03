package llmredteam

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/ClatTribe/tsengine/internal/cloudengine"
)

// RunEngagement runs the attacker against one target. llm=nil uses the
// deterministic Prober (CI-safe); pass a real cloudengine.LLM for the live brain.
func RunEngagement(ctx context.Context, llm cloudengine.LLM, target Target, eng *Engagement, opts Options) (*Report, error) {
	if llm == nil {
		llm = NewProber()
	}
	cc := &Context{Target: target, Eng: eng}
	return Investigate(ctx, llm, cc, opts)
}

// Score is the population result vs the ground-truth manifest.
type Score struct {
	Seed          int64    `json:"seed"`
	VulnTotal     int      `json:"vuln_total"`
	VulnCracked   int      `json:"vuln_cracked"`
	Recall        float64  `json:"recall"`
	HardenedTotal int      `json:"hardened_total"`
	FalseBreaches int      `json:"false_breaches"` // breaches recorded against hardened targets
	Missed        []string `json:"missed,omitempty"`
	Pass          bool     `json:"pass"`
}

// ScorePopulation runs the attacker against every target in a range and scores it.
func ScorePopulation(ctx context.Context, llm cloudengine.LLM, rg *Range, opts Options) (Score, []*Report, error) {
	s := Score{Seed: rg.Manifest.Seed}
	var reports []*Report
	for _, spec := range rg.Manifest.Targets {
		rep, err := RunEngagement(ctx, llm, rg.Target(spec.ID), rg.Engagement(spec.ID), opts)
		if err != nil {
			return s, reports, fmt.Errorf("target %s: %w", spec.ID, err)
		}
		reports = append(reports, rep)
		cracked := len(rep.Breaches) > 0
		if spec.Vulnerable {
			s.VulnTotal++
			if cracked {
				s.VulnCracked++
			} else {
				s.Missed = append(s.Missed, spec.ID+":"+spec.Weakness)
			}
		} else {
			s.HardenedTotal++
			if cracked {
				s.FalseBreaches++ // a hardened target should NEVER yield a grounded breach
			}
		}
	}
	if s.VulnTotal > 0 {
		s.Recall = float64(s.VulnCracked) / float64(s.VulnTotal)
	} else {
		s.Recall = 1
	}
	sort.Strings(s.Missed)
	s.Pass = s.VulnCracked == s.VulnTotal && s.FalseBreaches == 0
	return s, reports, nil
}

// RenderScore formats a population scorecard.
func RenderScore(s Score) string {
	verdict := "PASS"
	if !s.Pass {
		verdict = "FAIL"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "seed=%d  recall=%.0f%% (%d/%d vulnerable cracked)  false_breaches=%d/%d hardened  verdict=%s\n",
		s.Seed, s.Recall*100, s.VulnCracked, s.VulnTotal, s.FalseBreaches, s.HardenedTotal, verdict)
	if len(s.Missed) > 0 {
		fmt.Fprintf(&b, "  missed: %s\n", strings.Join(s.Missed, ", "))
	}
	return b.String()
}
