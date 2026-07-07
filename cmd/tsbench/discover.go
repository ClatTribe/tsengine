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
	"github.com/ClatTribe/tsengine/internal/correlate"
)

// countImpacts is the number of ground-truth high-impact findings in a scenario (for the e2e run summary).
func countImpacts(sc bench.DiscoveryScenario) int {
	n := 0
	for _, f := range sc.Findings {
		if f.HighImpact {
			n++
		}
	}
	return n
}

// discover.go is `tsbench discover` — the IMPACT-DISCOVERY runner. It presents the AI Security Engineer a
// noisy code+cloud estate (findings + facts + detail) and asks it to identify which findings create REAL
// organisational impact (reach a crown jewel — customer data / admin / financial, often via a cross-surface
// chain). bench.ScoreDiscovery grades recall (never miss the impactful one), precision (don't cry wolf),
// and grounding (§10). The engineer's brain is cloudengine.LLMFromEnv (the proxy in dev, the customer key
// in prod); --answer-file supplies the picks with no model (CI/demo).

func discoverCmd(argv []string) error {
	fs := flag.NewFlagSet("discover", flag.ContinueOnError)
	scenario := fs.String("scenario", "", "path to a discovery scenario JSON (a noisy estate)")
	fromScan := fs.String("from-scan", "", "END-TO-END: derive the estate from a real scan (assets+findings) via crossdetect, ground truth = the engine's chains")
	ledger := fs.String("ledger", "", "optional append-only ledger (.jsonl)")
	answerFile := fs.String("answer-file", "", "DEV/CI: supply the engineer's picks from a file (HIGH_IMPACT: line) instead of the LLM")
	if err := fs.Parse(argv); err != nil {
		return err
	}
	if *scenario == "" && *fromScan == "" {
		return fmt.Errorf("one of --scenario or --from-scan is required")
	}

	var sc bench.DiscoveryScenario
	if *fromScan != "" {
		raw, rerr := os.ReadFile(*fromScan) //nolint:gosec // operator-supplied bench fixture
		if rerr != nil {
			return rerr
		}
		var in bench.ScanInput
		if jerr := json.Unmarshal(raw, &in); jerr != nil {
			return fmt.Errorf("parse scan: %w", jerr)
		}
		var chains []correlate.Chain
		sc, chains = bench.EstateFromFindings("scan-e2e", in)
		fmt.Printf("substrate surfaced %d cross-surface chain(s) from %d findings; %d ground-truth impacts\n",
			len(chains), len(in.Findings), countImpacts(sc))
	} else {
		raw, rerr := os.ReadFile(*scenario) //nolint:gosec // operator-supplied bench fixture
		if rerr != nil {
			return rerr
		}
		if jerr := json.Unmarshal(raw, &sc); jerr != nil {
			return fmt.Errorf("parse scenario: %w", jerr)
		}
	}
	if sc.ID == "" || len(sc.Findings) == 0 {
		return fmt.Errorf("scenario needs an id + findings")
	}

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
			return fmt.Errorf("discover needs an LLM (the engineer's brain): set LLM_BASE_URL/LLM_MODEL/LLM_API_KEY (the proxy) or ANTHROPIC_API_KEY — or pass --answer-file")
		}
		out, gerr := llm.Generate(context.Background(), buildDiscoveryPrompt(sc))
		if gerr != nil {
			return fmt.Errorf("engineer LLM: %w", gerr)
		}
		reply, model = out, firstNonEmptyEnv("LLM_MODEL", "ANTHROPIC_MODEL")
	}

	d := parseDiscovery(reply)
	score := bench.ScoreDiscovery(sc, d)
	fmt.Println(bench.RenderDiscoveryScore(score))
	if *ledger != "" {
		line, _ := json.Marshal(map[string]any{
			"scenario_id": score.ScenarioID, "model": model, "pass": score.Pass(),
			"recall": score.Recall, "precision": score.Precision, "missed": len(score.Missed),
			"false_alarms": score.FP, "invented": len(score.Invented),
		})
		f, oerr := os.OpenFile(*ledger, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644) //nolint:gosec // bench path
		if oerr == nil {
			_, _ = f.Write(append(line, '\n'))
			_ = f.Close()
		}
	}
	return nil
}

// buildDiscoveryPrompt presents the noisy estate and asks the engineer to surface only the findings that
// create REAL organisational impact. The facts + detail come from the substrate; the engineer reasons over
// them — the impactful ones often require reading the detail (a chain, a mis-tag), not trusting severity.
func buildDiscoveryPrompt(sc bench.DiscoveryScenario) string {
	var b strings.Builder
	b.WriteString("You are the AI Security Engineer. Below is the organisation's open finding backlog across\n")
	b.WriteString("code and cloud. Most of it is noise. Your job: identify ONLY the findings that create REAL\n")
	b.WriteString("organisational impact — those that reach a CROWN JEWEL (customer/regulated data, admin/root, or\n")
	b.WriteString("a financial system), INCLUDING via a cross-surface chain (e.g. a leaked key in code that\n")
	b.WriteString("unlocks a cloud data store). Do NOT flag scary-but-contained findings (a critical RCE on an\n")
	b.WriteString("isolated throwaway box, a high CVE that isn't reachable) — read each finding's detail and judge\n")
	b.WriteString("REAL impact, not raw severity. Do not claim impact the facts don't support.\n\n")
	if len(sc.Context) > 0 {
		b.WriteString("ESTATE CONTEXT (raw facts — CORRELATE these with the findings to trace what actually\nreaches a crown jewel; the impact is NOT stated in any single finding):\n")
		for _, c := range sc.Context {
			b.WriteString("- " + c + "\n")
		}
		b.WriteByte('\n')
	}
	b.WriteString("FINDINGS:\n")
	for _, f := range sc.Findings {
		fmt.Fprintf(&b, "- id=%s | surface=%s | severity=%s | %s\n", f.ID, f.Surface, f.Severity, f.Title)
		if strings.TrimSpace(f.Detail) != "" {
			fmt.Fprintf(&b, "    detail: %s\n", f.Detail)
		}
	}
	b.WriteString("\nRespond with EXACTLY one line:\n")
	b.WriteString("HIGH_IMPACT: <comma-separated ids of the findings that create real organisational impact>\n")
	return b.String()
}

// parseDiscovery extracts the HIGH_IMPACT ids. Unknown ids are kept (ScoreDiscovery flags them as invented).
// Sentinel "empty" tokens (none / n/a / - / nothing) are dropped: the correct answer to a clean estate is
// "flag nothing", and a model naturally writes "HIGH_IMPACT: none" — which must parse to zero picks, not an
// invented id. Without this the zero-impact precision-floor test would falsely fail a correct engineer.
func parseDiscovery(reply string) bench.EngineerDiscovery {
	var d bench.EngineerDiscovery
	for _, ln := range strings.Split(reply, "\n") {
		ln = strings.TrimSpace(ln)
		if strings.HasPrefix(strings.ToUpper(ln), "HIGH_IMPACT:") {
			for _, id := range splitIDs(ln[len("HIGH_IMPACT:"):]) {
				if isEmptySentinel(id) {
					continue
				}
				d.HighImpactIDs = append(d.HighImpactIDs, id)
			}
		}
	}
	return d
}

// isEmptySentinel reports whether a token is a "no picks" marker rather than a finding id.
func isEmptySentinel(id string) bool {
	switch strings.ToLower(strings.Trim(id, "()[].")) {
	case "none", "n/a", "na", "nothing", "empty", "-":
		return true
	}
	return false
}
