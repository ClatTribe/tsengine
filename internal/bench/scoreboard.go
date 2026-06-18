package bench

import (
	"fmt"
	"sort"
	"strings"
)

// The unified competitive scoreboard — Track 1 / A2 of docs/competitive-roadmap.md.
// One artifact answering "where do we stand vs every competitor, in every
// category". It does NOT run the benches (they need live targets / the sandbox);
// it composes the published competitor leaderboards (the same Competitors cites
// the per-asset reports use) with our latest MEASURED numbers and renders an
// at-par verdict per category. Regenerate after a bench run:
//
//	tsbench scoreboard --results scoreboard.results.json --out SCOREBOARD.md

// ScoreCategory is one benchmark lane: what we measure, the at-par bar, and the
// competitor leaderboard. Higher is better for every metric here.
type ScoreCategory struct {
	Key         string      // stable id, also the results.json key
	Name        string      // human label
	Metric      string      // what the number means
	Bar         float64     // at-par threshold, as a fraction
	BarNote     string      // what the bar represents (which competitor)
	Competitors Competitors // the published leaderboard cite
}

// scoreboardCategories is the single source of truth for the competitive bar
// across every lane. Order = the rendered order. Reuses the per-asset
// Competitors vars so the bar can never drift from the per-bench reports.
func scoreboardCategories() []ScoreCategory {
	ossParity := Competitors{
		Leaderboard: "standalone OSS tool (per-tool recall parity, CLAUDE.md §2.4)",
		Note:        "No neutral public leaderboard — best-in-class = recall == the wrapped OSS tool run standalone (delta ≥ 0).",
	}
	return []ScoreCategory{
		{
			Key: "web_dast", Name: "Web app · DAST", Metric: "per-class Youden (TPR−FPR)",
			Bar: 0.56, BarNote: "OWASP-ZAP 56% (best OSS DAST); commercial ceiling Acunetix/Netsparker 87%",
			Competitors: wavsepCompetitors,
		},
		{
			Key: "repo_sast", Name: "Repository · SAST", Metric: "overall Youden",
			Bar: 0.35, BarNote: "Fortify 35%; ceiling Veracode 51%",
			Competitors: sastCompetitors,
		},
		{
			Key: "l2_agent", Name: "L2 agent · autonomy", Metric: "detection_rate (must-find) + verified_rate",
			Bar: 1.0, BarNote: "must-find parity (detection_rate = 1.0), zero FP; verified_rate the differentiator",
			Competitors: agentCompetitors,
		},
		{
			Key: "cloud_cspm", Name: "Cloud account · CSPM", Metric: "CIS-section recall",
			Bar: 1.0, BarNote: "must-find CIS recall (Prowler/Scout/Wiz self-publish — no neutral leaderboard)",
			Competitors: cloudCompetitors,
		},
		{Key: "parity_api", Name: "API · recall parity", Metric: "recall vs standalone OSS", Bar: 1.0, BarNote: "orchestration drops nothing the standalone tool found", Competitors: ossParity},
		{Key: "parity_ip", Name: "IP/host · recall parity", Metric: "recall vs standalone OSS", Bar: 1.0, BarNote: "orchestration drops nothing the standalone tool found", Competitors: ossParity},
		{Key: "parity_domain", Name: "Domain · recall parity", Metric: "recall vs standalone OSS", Bar: 1.0, BarNote: "orchestration drops nothing the standalone tool found", Competitors: ossParity},
		{Key: "parity_container", Name: "Container · SCA recall parity", Metric: "recall vs standalone OSS", Bar: 1.0, BarNote: "orchestration drops nothing the standalone tool found", Competitors: ossParity},
	}
}

// statusFor classifies our measured value against the at-par bar.
func statusFor(measured, bar float64) string {
	switch {
	case measured < 0:
		return "not_run"
	case measured+1e-9 >= bar:
		return "met"
	default:
		return "below"
	}
}

var statusBadge = map[string]string{
	"met":     "✅ at/above par",
	"below":   "⚠️ below",
	"not_run": "— pending run",
}

// Scoreboard renders the competitive scorecard as Markdown. results maps a
// category Key → our measured value as a fraction (0–1); a missing key renders
// as "pending a live run" (the bar still shows, so the target is always visible).
func Scoreboard(results map[string]float64) string {
	cats := scoreboardCategories()
	var b strings.Builder
	b.WriteString("# tsengine competitive scoreboard\n\n")
	b.WriteString("_Track 1 verification artifact (`docs/competitive-roadmap.md`). " +
		"Regenerate after a bench run: `tsbench scoreboard --results <json> --out SCOREBOARD.md`._\n\n")
	b.WriteString("| Category | Metric | Ours | At-par bar | Status |\n")
	b.WriteString("|---|---|---|---|---|\n")

	met, below, notrun := 0, 0, 0
	for _, c := range cats {
		val := -1.0
		if m, ok := results[c.Key]; ok {
			val = m
		}
		st := statusFor(val, c.Bar)
		switch st {
		case "met":
			met++
		case "below":
			below++
		default:
			notrun++
		}
		ours := "— not run"
		if val >= 0 {
			ours = fmt.Sprintf("%.0f%%", val*100)
		}
		fmt.Fprintf(&b, "| %s | %s | %s | %.0f%% — %s | %s |\n",
			c.Name, c.Metric, ours, c.Bar*100, c.BarNote, statusBadge[st])
	}
	fmt.Fprintf(&b, "\n**Summary:** %d at/above par · %d below · %d pending a live run.\n\n", met, below, notrun)

	b.WriteString("## Competitor leaderboards (the bar)\n\n")
	seen := map[string]bool{}
	for _, c := range cats {
		lb := c.Competitors.Leaderboard
		if lb == "" || seen[lb] {
			continue
		}
		seen[lb] = true
		fmt.Fprintf(&b, "- **%s** — %s", c.Name, lb)
		if len(c.Competitors.Scores) > 0 {
			names := make([]string, 0, len(c.Competitors.Scores))
			for n := range c.Competitors.Scores {
				names = append(names, n)
			}
			sort.Strings(names)
			parts := make([]string, 0, len(names))
			for _, n := range names {
				parts = append(parts, fmt.Sprintf("%s %s", n, c.Competitors.Scores[n]))
			}
			fmt.Fprintf(&b, " (%s)", strings.Join(parts, " / "))
		}
		b.WriteString("\n")
	}
	return b.String()
}
