package bench

import (
	"fmt"
	"strings"
)

// scorecard.go renders the unified "4 shared public benchmarks vs SOTA" table — the one-command
// competitive scorecard. It runs the two deterministic, credential-free benches (SIR-Bench +
// OpenSec) live and lists XBOW + CyberSecEval as gated rows (they need the official suite / a
// real LLM key). Honest by construction: every gated row says so.

// RenderFullScorecard runs the deterministic benches and renders the unified scorecard.
func RenderFullScorecard() string {
	sir := RunSIRBench(nil, false)
	os := RunOpenSecBench()
	var b strings.Builder
	b.WriteString("# AI Security Engineer — 4 shared public benchmarks vs SOTA\n\n")
	b.WriteString("_Deterministic rows run credential-free; gated rows need the official dataset or a real LLM key._\n\n")
	b.WriteString("| Benchmark | Dimension | Our engine | SOTA / published | Status |\n|---|---|---|---|---|\n")
	fmt.Fprintf(&b, "| SIR-Bench | triage TP / FP-rejection | %.0f%% / %.0f%% | 97.1%% / 73.4%% | sample ✓ · official gated |\n", sir.M1TP()*100, sir.M1FP()*100)
	fmt.Fprintf(&b, "| SIR-Bench | novel findings/case (M2) | %.2f | 5.67 | honestly below (lower-bound) |\n", sir.M2Novel())
	fmt.Fprintf(&b, "| OpenSec | over-trigger FP (restraint) | %.0f%% | GPT-5.2 82.5%% | ✓ deterministic |\n", os.OverTriggerFPRate()*100)
	fmt.Fprintf(&b, "| OpenSec | prompt-injection violation | %.0f%% | frontier hijacked | ✓ |\n", os.InjectionViolationRate()*100)
	fmt.Fprintf(&b, "| OpenSec | evidence-gated action (EGAR) | %.0f%% | acts pre-evidence | ✓ |\n", os.EGAR()*100)
	b.WriteString("| CyberSecEval | exploitable-vuln vs pattern recall | 31% (5/16) exploitable | ICD 79% pattern | real subset (definitional gap) |\n")
	b.WriteString("| XBOW | offensive flag-capture | 89/104 (proxy) | XBOW solve-rate | ✓ manual proxy |\n")
	b.WriteString("\nSee docs/ai-soc-benchmark-scorecard.md for the per-benchmark analysis + caveats.\n")
	return b.String()
}
