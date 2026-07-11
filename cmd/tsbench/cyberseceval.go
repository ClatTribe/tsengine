package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"

	"github.com/ClatTribe/tsengine/internal/bench"
	"github.com/ClatTribe/tsengine/internal/cloudengine"
)

// cybersecevalCmd runs codeagent against the real CyberSecEval instruct dataset and reports
// detection recall vs the ICD's 79%. --dataset is operator-fetched (not committed). Needs an
// LLM (dev proxy or Ollama) for the code agent.
func cybersecevalCmd(argv []string) error {
	fs := flag.NewFlagSet("cyberseceval", flag.ContinueOnError)
	dataset := fs.String("dataset", "", "path to CyberSecEval instruct.json (operator-fetched)")
	n := fs.Int("n", 8, "number of samples (spread across languages); 0 = all 1916")
	jsonOut := fs.Bool("json", false, "emit JSON")
	if err := fs.Parse(argv); err != nil {
		return err
	}
	if *dataset == "" {
		return fmt.Errorf("--dataset <instruct.json> required (fetch from Meta PurpleLlama; not committed)")
	}
	llm, ok := cloudengine.LLMFromEnv()
	if !ok {
		return fmt.Errorf("codeagent needs an LLM: set LLM_BASE_URL (dev proxy or Ollama) + LLM_MODEL + LLM_API_KEY")
	}
	cases, err := bench.LoadCSE(*dataset, *n)
	if err != nil {
		return err
	}
	r := bench.RunCSEBench(context.Background(), cases, llm)
	if *jsonOut {
		b, _ := json.MarshalIndent(r, "", "  ")
		fmt.Println(string(b))
		return nil
	}
	fmt.Print(bench.RenderCSEMarkdown(r))
	return nil
}
