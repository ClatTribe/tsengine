package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/ClatTribe/tsengine/internal/bench"
	"github.com/ClatTribe/tsengine/internal/cloudengine"
)

// impact.go is `tsbench impact` — the IMPACT-ACCURACY runner (the OTHER half of the engineer's job). It
// presents the AI Security Engineer a seeded estate (findings + the substrate's grounded FACTS: severity,
// data-tier, crown-jewel reach) and asks it to PRIORITISE by real organisational impact + say which reach a
// crown jewel. bench.ScoreImpact grades whether it led with the real top-impact issues (not raw severity),
// identified the crown reaches, and invented nothing (§10). The engineer's brain is cloudengine.LLMFromEnv
// (the proxy in dev, the customer key in prod); --answer-file supplies the assessment deterministically for
// CI/demo with no model.

func impactCmd(argv []string) error {
	fs := flag.NewFlagSet("impact", flag.ContinueOnError)
	scenario := fs.String("scenario", "", "path to an impact scenario JSON")
	ledger := fs.String("ledger", "", "optional append-only ledger (.jsonl)")
	answerFile := fs.String("answer-file", "", "DEV/CI: supply the engineer's assessment from a file (RANKING:/CROWN: lines) instead of the LLM")
	naiveBaseline := fs.Bool("naive-baseline", false, "score the SUBSTRATE-ONLY baseline (rank by the tags, no LLM) — the number the AI engineer must beat")
	if err := fs.Parse(argv); err != nil {
		return err
	}
	if *scenario == "" {
		return fmt.Errorf("--scenario is required")
	}
	raw, err := os.ReadFile(*scenario) //nolint:gosec // operator-supplied bench fixture
	if err != nil {
		return err
	}
	var sc bench.ImpactScenario
	if err := json.Unmarshal(raw, &sc); err != nil {
		return fmt.Errorf("parse scenario: %w", err)
	}
	if sc.ID == "" || len(sc.Issues) == 0 {
		return fmt.Errorf("scenario needs an id + issues")
	}

	// Substrate-only baseline: rank by the tags, no LLM — the number the AI engineer must beat.
	if *naiveBaseline {
		score := bench.ScoreImpact(sc, bench.NaiveBaseline(sc))
		fmt.Println("substrate-only " + bench.RenderImpactScore(score))
		return nil
	}

	// Get the engineer's assessment: a fixed answer file (deterministic demo), else the LLM.
	var reply, model string
	if *answerFile != "" {
		b, rerr := os.ReadFile(*answerFile) //nolint:gosec // dev/CI answer
		if rerr != nil {
			return rerr
		}
		reply, model = string(b), "answer-file"
	} else {
		llm, ok := cloudengine.LLMFromEnv()
		if !ok {
			return fmt.Errorf("impact needs an LLM (the engineer's brain): set LLM_BASE_URL/LLM_MODEL/LLM_API_KEY (the proxy) or ANTHROPIC_API_KEY — or pass --answer-file")
		}
		out, gerr := llm.Generate(context.Background(), buildImpactPrompt(sc))
		if gerr != nil {
			return fmt.Errorf("engineer LLM: %w", gerr)
		}
		reply, model = out, firstNonEmptyEnv("LLM_MODEL", "ANTHROPIC_MODEL")
	}

	assessment := parseAssessment(reply, sc)
	score := bench.ScoreImpact(sc, assessment)
	fmt.Println(bench.RenderImpactScore(score))
	if *ledger != "" {
		line, _ := json.Marshal(map[string]any{
			"scenario_id": score.ScenarioID, "model": model, "pass": score.Pass(),
			"rank_quality": score.RankQuality, "crown_tp": score.CrownTP,
			"invented": len(score.Invented), "missed": len(score.Missed),
		})
		f, oerr := os.OpenFile(*ledger, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644) //nolint:gosec // bench path
		if oerr == nil {
			_, _ = f.Write(append(line, '\n'))
			_ = f.Close()
		}
	}
	return nil
}

// buildImpactPrompt presents the estate + the grounded facts and asks for a prioritisation. The facts
// (data-tier, crown reach) come from the deterministic substrate — the engineer reasons OVER them; it is
// NOT asked to recompute them. The ask is judgment: rank by REAL impact, not raw severity.
func buildImpactPrompt(sc bench.ImpactScenario) string {
	var b strings.Builder
	b.WriteString("You are the AI Security Engineer. Below are open findings across the organisation's estate,\n")
	b.WriteString("each with the facts our platform already established: its severity, the data-sensitivity tier of\n")
	b.WriteString("the asset it sits on (1=customer/regulated data, 2=standard, 3=low/throwaway), and whether an\n")
	b.WriteString("attack path from it REACHES A CROWN JEWEL (sensitive data or admin).\n\n")
	b.WriteString("Your job: prioritise these by REAL organisational impact — NOT by raw severity. A medium that\n")
	b.WriteString("reaches customer data matters more than a critical on a throwaway dev box. IMPORTANT: the tags can\n")
	b.WriteString("be WRONG — READ each finding's detail; a low-tagged asset whose detail reveals prod admin\n")
	b.WriteString("credentials (or the reverse) must be re-judged on the detail. Do not invent impact the facts don't support.\n\n")
	b.WriteString("FINDINGS:\n")
	for _, is := range sc.Issues {
		fmt.Fprintf(&b, "- id=%s | severity=%s | data_tier=%d | reaches_crown_jewel=%v | %s\n",
			is.ID, is.Severity, is.DataTier, is.ReachesCrown, is.Title)
		if strings.TrimSpace(is.Detail) != "" {
			fmt.Fprintf(&b, "    detail: %s\n", is.Detail)
		}
	}
	b.WriteString("\nRespond with EXACTLY two lines:\n")
	b.WriteString("RANKING: <issue ids, comma-separated, MOST impactful first>\n")
	b.WriteString("CROWN: <issue ids that reach a crown jewel, comma-separated (empty if none)>\n")
	return b.String()
}

// parseAssessment extracts the RANKING + CROWN lines into an EngineerAssessment. Unknown ids are ignored
// on the ranking; a CROWN id not in the estate is kept (ScoreImpact will flag it as invented).
func parseAssessment(reply string, sc bench.ImpactScenario) bench.EngineerAssessment {
	known := map[string]bool{}
	for _, is := range sc.Issues {
		known[is.ID] = true
	}
	a := bench.EngineerAssessment{CrownJewelClaims: map[string]bool{}}
	for _, ln := range strings.Split(reply, "\n") {
		ln = strings.TrimSpace(ln)
		up := strings.ToUpper(ln)
		if strings.HasPrefix(up, "RANKING:") {
			for _, id := range splitIDs(ln[len("RANKING:"):]) {
				if known[id] {
					a.RankedIssueIDs = append(a.RankedIssueIDs, id)
				}
			}
		} else if strings.HasPrefix(up, "CROWN:") {
			for _, id := range splitIDs(ln[len("CROWN:"):]) {
				a.CrownJewelClaims[id] = true
			}
		}
	}
	return a
}

func splitIDs(s string) []string {
	var out []string
	for _, part := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' || r == ';' }) {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}
	return out
}
