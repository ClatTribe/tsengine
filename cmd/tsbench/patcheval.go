package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/ClatTribe/tsengine/internal/bench"
	"github.com/ClatTribe/tsengine/internal/cloudengine"
	"github.com/ClatTribe/tsengine/internal/codeagent"
)

// tsbench patcheval — run the AI Security Engineer over PatchEval and write THEIR submission format.
//
// PatchEval (github.com/bytedance/PatchEval, Apache-2.0) supplies the tasks and the verdict; we supply
// the agent. There is no scoring here on purpose — their `run_eval.sh` decides inside their container,
// which is the entire reason for using a neutral benchmark.
//
// Sources come from a directory the caller materialised (their Docker image holds the repo). Rather
// than pretend we can fetch them, a case with no source on disk is SKIPPED LOUDLY and still gets an
// empty submission, so their denominator stays honest: 230 tasks in, 230 submissions out, and a
// failure looks like a failure rather than a missing file.
func patchevalCmd(argv []string) error {
	fs := flag.NewFlagSet("patcheval", flag.ContinueOnError)
	instances := fs.String("instances", "", "path to patcheval_verified.json (theirs; not vendored)")
	out := fs.String("out", "", "patches dir their evaluator mounts (…/agent_runs/<ts>-<prefix>/patches)")
	sources := fs.String("sources", "", "dir containing <cve-id>/ checkouts of each repo (materialised from their image)")
	attempts := fs.Int("attempts", 1, "propose attempts per case (their harness is the verifier, so >1 only re-prompts)")
	if err := fs.Parse(argv); err != nil {
		return err
	}
	if *instances == "" || *out == "" {
		return fmt.Errorf("--instances and --out are required")
	}

	xs, err := bench.LoadPatchEval(*instances)
	if err != nil {
		return err
	}
	llm, ok := cloudengine.LLMFromEnv()
	if !ok {
		return fmt.Errorf("no LLM configured — the engineer under test needs one (set LLM_API_KEY, or " +
			"LLM_BASE_URL + LLM_MODEL for a local model)")
	}

	ctx := context.Background()
	var proposed, skipped int
	for _, in := range xs {
		p := bench.PromptFields(in)
		sub := bench.PatchEvalSubmission{CVE: p.CVEID}

		src, serr := loadCaseSources(*sources, p.CVEID)
		if serr != nil || len(src) == 0 {
			// No source on disk → nothing honest to propose. Say so, and still submit an empty patch.
			fmt.Fprintf(os.Stderr, "  skip %s: %v\n", p.CVEID, firstErr(serr, fmt.Errorf("no sources found")))
			skipped++
			if werr := bench.WriteSubmission(*out, sub); werr != nil {
				return werr
			}
			continue
		}

		// Only what PatchEval lets an agent see: the CWE class, the repo, and the CVE description.
		f := codeagent.Finding{
			Class:    p.CWE,
			Endpoint: p.Repo,
			Detail:   p.Description,
		}
		patch, _, _, perr := codeagent.ProposePatchIterative(ctx, llm, f, src, nil, *attempts)
		if perr != nil {
			fmt.Fprintf(os.Stderr, "  fail %s: %v\n", p.CVEID, perr)
			if werr := bench.WriteSubmission(*out, sub); werr != nil {
				return werr
			}
			continue
		}

		// THE GUARD THAT MAKES THE RUN MEAN ANYTHING. The instance carries fix_func and patch_url; if
		// either reached the model, the score measures our plumbing rather than the engineer. Abort
		// the whole run — a partially-leaked result is worse than no result, because it looks fine.
		if got := bench.LeakedInto(patch.Raw, in); len(got) > 0 {
			return fmt.Errorf("ABORT: the answer leaked into the model exchange for %s (%s) — the run "+
				"would be measuring nothing", p.CVEID, strings.Join(got, ", "))
		}

		before := make(map[string]string, len(src))
		for _, s := range src {
			before[s.Path] = s.Content
		}
		sub.FixPatch = patch.UnifiedDiff(before)
		if strings.TrimSpace(sub.FixPatch) != "" {
			proposed++
		}
		if werr := bench.WriteSubmission(*out, sub); werr != nil {
			return werr
		}
	}

	// No leak count: a leak aborts the run above, so printing "0 leaks" every time would be noise
	// pretending to be a check.
	fmt.Printf("patcheval: %d instance(s) — %d patch(es) proposed, %d skipped (no sources)\n",
		len(xs), proposed, skipped)
	fmt.Println("NOT A SCORE. Run their evaluator to get one:")
	fmt.Println("  bash patcheval/exp_agent/run_eval.sh <prefix>")
	return nil
}

// loadCaseSources reads <dir>/<cve>/**/* as the repo snapshot for one case.
func loadCaseSources(root, cve string) ([]codeagent.SourceFile, error) {
	if strings.TrimSpace(root) == "" {
		return nil, fmt.Errorf("--sources not set")
	}
	base := filepath.Join(root, cve)
	var out []codeagent.SourceFile
	err := filepath.Walk(base, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil //nolint:nilerr // an unreadable entry is skipped, not fatal
		}
		b, rerr := os.ReadFile(p) //nolint:gosec // operator-supplied benchmark checkout
		if rerr != nil {
			return nil
		}
		rel, _ := filepath.Rel(base, p)
		out = append(out, codeagent.SourceFile{Path: rel, Content: string(b)})
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out, nil
}

func firstErr(errs ...error) error {
	for _, e := range errs {
		if e != nil {
			return e
		}
	}
	return nil
}
