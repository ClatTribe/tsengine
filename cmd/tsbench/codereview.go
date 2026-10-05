package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/ClatTribe/tsengine/internal/cloudengine"
	"github.com/ClatTribe/tsengine/internal/codelocalize"
	"github.com/ClatTribe/tsengine/internal/codereviewbench"
	"github.com/ClatTribe/tsengine/internal/codesweep"
)

// codereview.go is `tsbench codereview` — the held-out AI source-review benchmark
// (internal/codereviewbench). Three steps, kept separate so each can be checked on its own:
//
//	build  — turn published advisories into cases (pre-fix commit + the fix's changed lines)
//	run    — run a reviewer over every case and write its predictions (needs a model)
//	score  — grade a predictions file against the corpus (no model, no network)
//
// `score` being model-free is deliberate: anyone can re-grade a published predictions file and get the
// same number, and a reviewer we do not ship (deepsec run by hand, another vendor's export) can be
// scored on the same key.
func codereviewCmd(argv []string) error {
	if len(argv) == 0 {
		return errors.New("usage: tsbench codereview build|run|score [flags]")
	}
	switch argv[0] {
	case "build":
		return codereviewBuild(argv[1:])
	case "run":
		return codereviewRun(argv[1:])
	case "score":
		return codereviewScore(argv[1:])
	}
	return fmt.Errorf("unknown codereview step %q (build|run|score)", argv[0])
}

func codereviewBuild(argv []string) error {
	fs := flag.NewFlagSet("codereview build", flag.ContinueOnError)
	ghsa := fs.String("ghsa", "", "comma-separated GHSA ids")
	out := fs.String("out", "fixtures/codereview", "directory to write case JSON into")
	maxFiles := fs.Int("max-files", 5, "drop an advisory whose fix touches more source files than this")
	if err := fs.Parse(argv); err != nil {
		return err
	}
	if *ghsa == "" {
		return errors.New("--ghsa is required")
	}
	if err := os.MkdirAll(*out, 0o755); err != nil {
		return err
	}
	fetch := githubFetch()
	ctx := context.Background()
	built, skipped := 0, 0
	for _, id := range strings.Split(*ghsa, ",") {
		id = strings.TrimSpace(id)
		if id == "" {
			continue
		}
		c, err := codereviewbench.Build(ctx, fetch, id, codereviewbench.BuildOptions{MaxFiles: *maxFiles})
		var skip codereviewbench.ErrSkip
		switch {
		case errors.As(err, &skip):
			skipped++
			fmt.Printf("SKIP  %s — %s\n", id, skip.Reason)
			continue
		case err != nil:
			return fmt.Errorf("%s: %w", id, err)
		}
		b, _ := json.MarshalIndent(c, "", "  ")
		if err := os.WriteFile(filepath.Join(*out, c.ID+".json"), append(b, '\n'), 0o644); err != nil {
			return err
		}
		built++
		fmt.Printf("BUILT %s  %s @ %.10s  %d range(s) in %d file(s)\n", c.ID, c.Repo, c.PreFixCommit, len(c.Golden), len(c.Files()))
	}
	fmt.Printf("\n%d built, %d skipped (each skip says why — the corpus does not shrink silently)\n", built, skipped)
	return nil
}

// githubFetch GETs the GitHub REST API, authenticating with GITHUB_TOKEN (or `gh auth token`) when
// available — unauthenticated requests are rate-limited to 60/hour, which one build exhausts.
func githubFetch() codereviewbench.Fetch {
	token := os.Getenv("GITHUB_TOKEN")
	if token == "" {
		if out, err := exec.Command("gh", "auth", "token").Output(); err == nil {
			token = strings.TrimSpace(string(out))
		}
	}
	client := &http.Client{Timeout: 30 * time.Second}
	return func(ctx context.Context, apiPath string) ([]byte, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.github.com"+apiPath, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Accept", "application/vnd.github+json")
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
		if err != nil {
			return nil, err
		}
		if resp.StatusCode/100 != 2 {
			return nil, fmt.Errorf("GET %s: http %d", apiPath, resp.StatusCode)
		}
		return body, nil
	}
}

func codereviewRun(argv []string) error {
	fs := flag.NewFlagSet("codereview run", flag.ContinueOnError)
	corpusDir := fs.String("corpus", "fixtures/codereview", "case directory")
	reviewer := fs.String("tool", "codesweep", "reviewer to run (codesweep)")
	work := fs.String("work", "", "scratch directory for the pinned checkouts (default: a temp dir)")
	out := fs.String("out", "codereview-predictions.json", "predictions file to write")
	maxTasks := fs.Int("max-tasks", 60, "codesweep: cap on focused questions per case")
	only := fs.String("only", "", "comma-separated case ids to run (default: all)")
	localizer := fs.String("localizer", "llm", "how codesweep picks files to ask about: llm (what the product runs) or heuristic (free, deterministic — weaker, and reported as such)")
	if err := fs.Parse(argv); err != nil {
		return err
	}
	if *reviewer != "codesweep" {
		// deepsec is scored by running it by hand (it spends a real model budget per case) and passing its
		// export to `score --deepsec-dir`; this runner refuses rather than spending on the operator's behalf.
		return fmt.Errorf("run supports --tool codesweep; score deepsec from its own export with `score --deepsec-dir`")
	}
	cases, err := codereviewbench.Load(*corpusDir)
	if err != nil {
		return err
	}
	llm, ok := cloudengine.LLMFromEnv()
	if !ok {
		return errors.New("no model configured (ANTHROPIC_API_KEY / LLM_BASE_URL / ...) — a review benchmark with no reviewer measures nothing")
	}
	if *work == "" {
		if *work, err = os.MkdirTemp("", "codereview-"); err != nil {
			return err
		}
	}
	want := map[string]bool{}
	for _, id := range strings.Split(*only, ",") {
		if id = strings.TrimSpace(id); id != "" {
			want[id] = true
		}
	}
	model := ""
	if mn, ok := llm.(cloudengine.ModelNamer); ok {
		model = mn.ModelName()
	}
	tool := "codesweep"
	var loc codelocalize.Localizer = codelocalize.LLMLocalizer{LLM: llm}
	switch *localizer {
	case "llm":
	case "heuristic":
		tool = "codesweep(heuristic-plan)" // a different configuration must never be scored under the product's name
		loc = codelocalize.HeuristicLocalizer{}
	default:
		return fmt.Errorf("--localizer must be llm or heuristic")
	}
	preds := codereviewbench.Predictions{Tool: tool, Model: model,
		Cases: map[string][]codereviewbench.Prediction{}, Ran: map[string]bool{}, Errors: map[string]string{}}
	// RESUME: a previous run's results for the same configuration are kept, and the cases it finished are
	// skipped. A run is hours on a local model; losing it to a timeout at case 4 of 5 is the failure this
	// prevents (it happened).
	if raw, rerr := os.ReadFile(*out); rerr == nil {
		var prev codereviewbench.Predictions
		if json.Unmarshal(raw, &prev) == nil && prev.Tool == tool && prev.Model == model {
			preds = prev
			if preds.Cases == nil {
				preds.Cases = map[string][]codereviewbench.Prediction{}
			}
			if preds.Ran == nil {
				preds.Ran = map[string]bool{}
			}
			if preds.Errors == nil {
				preds.Errors = map[string]string{}
			}
		}
	}
	save := func() error {
		if ur, ok := llm.(cloudengine.UsageReporter); ok {
			// Only a model with a published price yields a cost. EstimateCost's default rate is right for a
			// budget (overstating is the safe direction there) and wrong for a published number: a local
			// model priced at a frontier rate is an invented cost.
			if u := ur.TotalUsage(); u.Total() > 0 && cloudengine.PriceKnown(model) {
				preds.CostUSD, preds.CostKnown = preds.CostUSD+cloudengine.EstimateCost(model, u), true
			}
		}
		b, _ := json.MarshalIndent(preds, "", "  ")
		return os.WriteFile(*out, b, 0o644)
	}
	ctx := context.Background()
	for _, c := range cases {
		if len(want) > 0 && !want[c.ID] {
			continue
		}
		if preds.Ran[c.ID] {
			fmt.Printf("DONE    %s (from an earlier run)\n", c.ID)
			continue
		}
		dir := filepath.Join(*work, c.ID)
		if err := checkout(ctx, c, dir); err != nil {
			preds.Errors[c.ID] = "checkout: " + err.Error()
			fmt.Printf("NOT RUN %s — %v\n", c.ID, err)
			continue
		}
		repo, err := codelocalize.LoadRepo(dir, codelocalize.LoadOptions{})
		if err != nil {
			preds.Errors[c.ID] = "load: " + err.Error()
			continue
		}
		tasks, err := codesweep.Plan(ctx, loc, repo, codesweep.PlanOptions{MaxTasks: *maxTasks})
		if err != nil {
			preds.Errors[c.ID] = "plan: " + err.Error()
			continue
		}
		res, err := codesweep.Sweep(ctx, llm, repo, tasks, codesweep.SweepOptions{})
		if err != nil {
			preds.Errors[c.ID] = "sweep: " + err.Error()
			continue
		}
		if preds.Examined == nil {
			preds.Examined = map[string][]string{}
		}
		seenPath := map[string]bool{}
		for _, tk := range tasks {
			if !seenPath[tk.Path] {
				seenPath[tk.Path] = true
				preds.Examined[c.ID] = append(preds.Examined[c.ID], tk.Path)
			}
		}
		var ps []codereviewbench.Prediction
		for _, cand := range res.Candidates {
			if !cand.Vulnerable {
				continue
			}
			for _, ev := range cand.Evidence {
				if p, ok := parseLoc(ev); ok {
					p.Rule = cand.CWE
					ps = append(ps, p)
				}
			}
		}
		preds.Cases[c.ID] = ps
		preds.Ran[c.ID] = true
		delete(preds.Errors, c.ID)
		fmt.Printf("RAN     %s — %d tasks planned, %d ran, %d candidate locations\n", c.ID, res.Planned, res.Ran, len(ps))
		if err := os.WriteFile(*out, mustIndent(preds), 0o644); err != nil { // after EVERY case
			return err
		}
	}
	if err := save(); err != nil {
		return err
	}
	fmt.Printf("\nwrote %s — grade it with `tsbench codereview score --predictions %s`\n", *out, *out)
	return nil
}

// checkout fetches exactly the pre-fix commit, shallow, so a case costs one commit's tree.
func checkout(ctx context.Context, c codereviewbench.Case, dir string) error {
	if _, err := os.Stat(filepath.Join(dir, ".git")); err == nil {
		return nil // already pinned by an earlier run
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	steps := [][]string{
		{"init", "-q"},
		{"remote", "add", "origin", "https://github.com/" + c.Repo + ".git"},
		{"fetch", "-q", "--depth", "1", "origin", c.PreFixCommit},
		{"checkout", "-q", "FETCH_HEAD"},
	}
	for _, s := range steps {
		cmd := exec.CommandContext(ctx, "git", s...)
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("git %s: %v: %s", s[0], err, strings.TrimSpace(string(out)))
		}
	}
	return nil
}

func mustIndent(v any) []byte {
	b, _ := json.MarshalIndent(v, "", "  ")
	return b
}

var locRe = regexp.MustCompile(`^(.+?):(\d+)`)

func parseLoc(s string) (codereviewbench.Prediction, bool) {
	m := locRe.FindStringSubmatch(strings.TrimSpace(s))
	if m == nil {
		return codereviewbench.Prediction{}, false
	}
	n, err := strconv.Atoi(m[2])
	if err != nil || n <= 0 {
		return codereviewbench.Prediction{}, false
	}
	return codereviewbench.Prediction{File: m[1], Line: n}, true
}

func codereviewScore(argv []string) error {
	fs := flag.NewFlagSet("codereview score", flag.ContinueOnError)
	corpusDir := fs.String("corpus", "fixtures/codereview", "case directory")
	predsPath := fs.String("predictions", "", "predictions JSON written by `codereview run`")
	deepsecDir := fs.String("deepsec-dir", "", "score deepsec instead: a directory holding one deepsec `export --format json` file per case, named <case-id>.json")
	tol := fs.Int("tolerance", codereviewbench.DefaultTolerance, "lines either side of a fixed line that still count")
	cutoff := fs.String("cutoff", "", "model training cutoff YYYY-MM-DD — reports how many cases were published after it")
	out := fs.String("out", "", "also write the markdown report here")
	asJSON := fs.Bool("json", false, "print the score as JSON")
	if err := fs.Parse(argv); err != nil {
		return err
	}
	cases, err := codereviewbench.Load(*corpusDir)
	if err != nil {
		return err
	}
	var preds codereviewbench.Predictions
	switch {
	case *deepsecDir != "":
		if preds, err = deepsecPredictions(cases, *deepsecDir); err != nil {
			return err
		}
	case *predsPath != "":
		raw, rerr := os.ReadFile(*predsPath)
		if rerr != nil {
			return rerr
		}
		if err := json.Unmarshal(raw, &preds); err != nil {
			return fmt.Errorf("predictions: %w", err)
		}
	default:
		return errors.New("one of --predictions or --deepsec-dir is required")
	}
	s := codereviewbench.ScoreAll(cases, preds, *tol, *cutoff)
	if *asJSON {
		b, _ := json.MarshalIndent(s, "", "  ")
		fmt.Println(string(b))
	} else {
		fmt.Print(codereviewbench.Render(s))
	}
	if *out != "" {
		return os.WriteFile(*out, []byte(codereviewbench.Render(s)), 0o644)
	}
	return nil
}

// deepsecPredictions reads deepsec exports. A case with no export file did not run — never a miss.
func deepsecPredictions(cases []codereviewbench.Case, dir string) (codereviewbench.Predictions, error) {
	p := codereviewbench.Predictions{Tool: "deepsec", Cases: map[string][]codereviewbench.Prediction{},
		Ran: map[string]bool{}, Errors: map[string]string{}}
	for _, c := range cases {
		raw, err := os.ReadFile(filepath.Join(dir, c.ID+".json"))
		if err != nil {
			p.Errors[c.ID] = "no deepsec export for this case"
			continue
		}
		// deepsec 2.x `export --format json`: a flat list whose locations live under "metadata".
		var rows []struct {
			Metadata struct {
				FilePath    string `json:"filePath"`
				LineNumbers []int  `json:"lineNumbers"`
				VulnSlug    string `json:"vulnSlug"`
			} `json:"metadata"`
		}
		if err := json.Unmarshal(raw, &rows); err != nil {
			return p, fmt.Errorf("%s: deepsec export: %w", c.ID, err)
		}
		var ps []codereviewbench.Prediction
		for _, r := range rows {
			for _, l := range r.Metadata.LineNumbers {
				ps = append(ps, codereviewbench.Prediction{File: r.Metadata.FilePath, Line: l, Rule: r.Metadata.VulnSlug})
			}
		}
		p.Cases[c.ID] = ps
		p.Ran[c.ID] = true
	}
	return p, nil
}
