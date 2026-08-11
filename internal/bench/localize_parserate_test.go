package bench

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/internal/cloudengine"
	"github.com/ClatTribe/tsengine/internal/codelocalize"
)

// TestLocalizeParseRate separates two failure modes that the headline recall number CANNOT tell apart,
// and which mean opposite things about a model.
//
// LLMLocalizer degrades silently to the heuristic when the model errors OR returns an unparseable
// proposal (see codelocalize/llm.go — deliberate, so a broken model never yields a falsely-confident
// ranking). The consequence for benchmarking is that a model which never produced a usable answer
// scores EXACTLY the deterministic substrate — identical to a model that reasoned carefully and simply
// agreed with it. "+0.00 lift" is therefore ambiguous on its own:
//
//   - the model ran, ranked, and added nothing        -> a real result about security reasoning
//   - the model never emitted parseable output        -> a result about FORMAT ADHERENCE, not security
//
// This surfaced for real. Foundation-Sec-8B-Instruct measured +0.00 median lift, which read as "the
// security model does not help here"; the trace showed it was actually producing unparseable output on
// roughly one scenario in six (and a different scenario each run), silently falling back. It genuinely
// reasoned on the rest — so the honest reading is "partly weaker ranking, partly a formatting gap",
// not the flat verdict the headline number implied.
//
// Any future model comparison must report this alongside recall, or it risks attributing a harness
// artifact to model quality. Skipped without a configured LLM, so CI is unaffected.
func TestLocalizeParseRate(t *testing.T) {
	llm, ok := cloudengine.LLMFromEnv()
	if !ok {
		t.Skip("no LLM configured (set LLM_BASE_URL + LLM_MODEL, or an API key) — parse-rate needs a live model")
	}

	scenarios := LocalizeHardScenarios()
	var unparseable, unreachable []string
	for _, sc := range scenarios {
		res, err := codelocalize.LLMLocalizer{LLM: llm}.Localize(context.Background(), sc.Query, sc.Repo)
		if err != nil {
			t.Fatalf("%s: localize: %v", sc.Name, err)
		}
		for _, tr := range res.Trace {
			// These two look identical in the recall number and mean opposite things, so they are
			// counted separately. "model unavailable" is TRANSPORT (network, 429, bad key) and says
			// nothing about the model; "no parseable proposal" means it answered in a shape the
			// harness could not read, which IS a property of the model worth reporting.
			switch {
			case strings.Contains(tr, "model unavailable"):
				unreachable = append(unreachable, sc.Name)
			case strings.Contains(tr, "no parseable proposal"):
				unparseable = append(unparseable, sc.Name)
			}
		}
	}

	// A model we could not reach tells us nothing at all — skip rather than report a verdict on it.
	// This matters in practice: a stray LLM_API_KEY in the environment resolves a cloud provider that
	// may be rate-limited, and counting those 429s as "unparseable" would slander whichever model the
	// operator thought they were testing.
	if len(unreachable) == len(scenarios) {
		t.Skipf("model unreachable on all %d scenarios (transport, not format) — nothing to measure",
			len(scenarios))
	}

	usable := len(scenarios) - len(unparseable) - len(unreachable)
	fmt.Printf("parse-rate: %d/%d usable", usable, len(scenarios))
	if len(unparseable) > 0 {
		fmt.Printf("  — UNPARSEABLE on: %s", strings.Join(unparseable, ", "))
	}
	if len(unreachable) > 0 {
		fmt.Printf("  — unreachable on: %s", strings.Join(unreachable, ", "))
	}
	fmt.Println()

	// A low parse rate is a finding to REPORT, not a build failure — which model is configured is the
	// operator's choice. But if a reachable model never once produced a usable proposal, the ablation
	// measured the harness rather than the model, and publishing that as a model verdict would be wrong.
	if usable == 0 {
		t.Errorf("parse-rate 0/%d usable from a REACHABLE model — any recall delta measured against it "+
			"reflects the harness, not the model. Check the chat template and expected output format "+
			"before drawing a conclusion.", len(scenarios))
	}
}
