package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"

	"github.com/ClatTribe/tsengine/internal/bench"
	"github.com/ClatTribe/tsengine/internal/cloudengine"
)

// cvepatchCmd runs the AI Security Engineer's code-fix (codeagent.ProposePatch) over real app-sec CVE
// instances and scores produced/localized vs the gold patch. The `fixed` verdict needs a judge (an
// execution oracle or a frontier proxy) — emitted with the patches so it can be judged out of band.
// ProposePatch is single-shot, so even the manual dev proxy can drive a real run.
func cvepatchCmd(argv []string) error {
	fs := flag.NewFlagSet("cvepatch", flag.ContinueOnError)
	dataset := fs.String("dataset", "", "path to the real-CVE instance set (JSON array; operator-provided, not committed)")
	asJSON := fs.Bool("json", false, "emit per-instance results (incl. proposed patches) as JSON for a judge")
	if err := fs.Parse(argv); err != nil {
		return err
	}
	if *dataset == "" {
		return fmt.Errorf("--dataset is required (a real app-sec CVE set; disk-light, not committed)")
	}
	instances, err := bench.LoadCVEPatch(*dataset)
	if err != nil {
		return err
	}
	llm, ok := cloudengine.LLMFromEnv()
	if !ok {
		return fmt.Errorf("codeagent needs an LLM: set LLM_BASE_URL (dev proxy or Ollama) + LLM_MODEL [+ LLM_API_KEY]")
	}
	results := bench.RunCVEPatchBench(context.Background(), instances, llm)
	if *asJSON {
		// include the proposed patches so an out-of-band judge (proxy/oracle) can set `fixed`.
		type out struct {
			bench.CVEPatchResult
			ProposedFiles []patchOut `json:"proposed_files"`
		}
		var os_ []out
		for _, r := range results {
			var pf []patchOut
			for _, f := range r.Patch().Files {
				pf = append(pf, patchOut{Path: f.Path, Content: f.Content})
			}
			os_ = append(os_, out{CVEPatchResult: r, ProposedFiles: pf})
		}
		b, _ := json.MarshalIndent(os_, "", "  ")
		fmt.Println(string(b))
		return nil
	}
	fmt.Print(bench.RenderCVEPatchMarkdown(results))
	return nil
}

type patchOut struct {
	Path    string `json:"path"`
	Content string `json:"content"`
}
