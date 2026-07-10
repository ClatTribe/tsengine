package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"

	"github.com/ClatTribe/tsengine/internal/bench"
	"github.com/ClatTribe/tsengine/internal/l2"
)

// l2leadCmd runs the L2 LEAD triage benchmark: the generalist reasons over the cross-surface
// correlation estate (unified issues + attack chains) and is scored on whether it surfaced the
// cross-surface attack path, led with the crown-jewel chain, and stayed grounded. Needs an
// l2.Client via the env (the dev proxy = frontier Claude: LLM_BASE_URL=…:8898/v1). Skips
// honestly when no client is configured.
func l2leadCmd(argv []string) error {
	fs := flag.NewFlagSet("l2lead", flag.ContinueOnError)
	jsonOut := fs.Bool("json", false, "emit the result as JSON")
	if err := fs.Parse(argv); err != nil {
		return err
	}
	client := l2.ClientFromEnv()
	if client == nil {
		fmt.Println("L2 Lead bench SKIPPED — no LLM client configured. Set LLM_BASE_URL to the dev proxy (frontier Claude) or a local Ollama + LLM_MODEL + LLM_API_KEY.")
		return nil
	}
	r := bench.RunL2LeadBench(context.Background(), client)
	if *jsonOut {
		b, _ := json.MarshalIndent(r, "", "  ")
		fmt.Println(string(b))
		return nil
	}
	fmt.Print(bench.RenderL2LeadMarkdown(r))
	return nil
}
