package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/ClatTribe/tsengine/internal/bench"
	"github.com/ClatTribe/tsengine/internal/cloudengine"
)

// replayLLM replays pre-generated fixes so any external agent (incl. the manual frontier proxy) can
// generate offline, then run through the REAL ProposePatch(Iterative) parse + scoring — no fragile
// concurrent HTTP relay. It tracks instance + attempt so the propose→verify→REFINE loop works: a
// NON-refine prompt marks a new instance (the loop always starts an instance with buildPatchPrompt);
// a refine prompt bumps the attempt. Response files: <id>.txt (attempt 1) then <id>.<n>.txt (refines).
type replayLLM struct {
	ids     []string // instance IDs in processing order
	dir     string
	instIdx int
	attempt int
}

func newReplayLLM(dir string, ids []string) *replayLLM {
	return &replayLLM{ids: ids, dir: dir, instIdx: -1}
}

func (r *replayLLM) Generate(_ context.Context, prompt string) (string, error) {
	if strings.Contains(prompt, "VERIFIER OUTPUT (why your last patch failed)") {
		r.attempt++
	} else {
		r.instIdx++
		r.attempt = 1
	}
	if r.instIdx < 0 || r.instIdx >= len(r.ids) {
		return "", fmt.Errorf("replay: instance index %d out of range", r.instIdx)
	}
	id := r.ids[r.instIdx]
	cands := []string{fmt.Sprintf("%s.%d.txt", id, r.attempt)}
	if r.attempt == 1 {
		cands = append(cands, id+".txt")
	}
	for _, c := range cands {
		if b, err := os.ReadFile(filepath.Join(r.dir, filepath.Clean(c))); err == nil { //nolint:gosec // operator dir
			return string(b), nil
		}
	}
	return "", fmt.Errorf("replay: no response file for %s attempt %d", id, r.attempt)
}

// cvepatchCmd runs the AI Security Engineer's code-fix (codeagent.ProposePatch) over real app-sec CVE
// instances and scores produced/localized vs the gold patch. The `fixed` verdict needs a judge (an
// execution oracle or a frontier proxy) — emitted with the patches so it can be judged out of band.
// ProposePatch is single-shot, so even the manual dev proxy can drive a real run.
func cvepatchCmd(argv []string) error {
	fs := flag.NewFlagSet("cvepatch", flag.ContinueOnError)
	dataset := fs.String("dataset", "", "path to the real-CVE instance set (JSON array; operator-provided, not committed)")
	asJSON := fs.Bool("json", false, "emit per-instance results (incl. proposed patches) as JSON for a judge")
	responses := fs.String("responses", "", "dir of pre-generated fixes (<id>.txt, <id>.<n>.txt for refines) — replay a proxy/offline run through the real scoring")
	refine := fs.Int("refine", 1, "max propose→verify→refine attempts per instance (1 = single-shot baseline; needs an execution oracle to refine)")
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
	var llm interface {
		Generate(context.Context, string) (string, error)
	}
	if *responses != "" {
		ids := make([]string, len(instances))
		for i, in := range instances {
			ids[i] = in.ID
		}
		llm = newReplayLLM(*responses, ids)
	} else {
		live, ok := cloudengine.LLMFromEnv()
		if !ok {
			return fmt.Errorf("codeagent needs an LLM: set LLM_BASE_URL (dev proxy or Ollama) + LLM_MODEL [+ LLM_API_KEY], or use --responses <dir>")
		}
		llm = live
	}
	results := bench.RunCVEPatchBenchN(context.Background(), instances, llm, *refine)
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
