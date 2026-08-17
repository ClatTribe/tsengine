package bench

import (
	"context"
	"fmt"
	"sort"
)

// BackportBench scoring — the task-8 (backport) benchmark.
//
// THE ORACLE IS EXECUTION, NOT CLASSIFICATION.
//
// BackportBench (arXiv 2512.01396) is 202 real backporting tasks from 12
// repositories across three ecosystems (PyPI / Maven / npm), each shipped with a
// Dockerized environment, the upstream fix, the historical target version, and
// the MAINTAINER'S OWN backport plus the relevant tests. It is scored
// test-driven: a task is resolved only when the candidate backport makes the
// repo's tests pass in that environment.
//
// That distinction matters for us. `internal/backport` produces verdicts
// (clean / offset / needs_adaptation / …) which are a SAFETY mechanism — they
// stop us shipping a patch we could not place. They are NOT the benchmark
// metric, and a "clean" verdict is not evidence the backport is correct. Only
// the tests are. So this scorer takes an execution Runner and never treats a
// solver's own confidence as success (the §10 rule applied to benchmarking: the
// system under test does not get to grade itself).
//
// NO DATASET, NO NUMBER. The concrete loader for the released BackportBench
// task format is deliberately absent: fabricating a schema would produce a
// number that looks real and is not. `Load` is the documented seam an operator
// fills once the dataset is fetched (it is Dockerized and large — an
// out-of-band step, like the WAVSEP and OWASP-Benchmark corpora).

// BackportInstance is one benchmark task, in the neutral shape this scorer
// needs. Field meanings follow BackportBench's task definition.
type BackportInstance struct {
	ID            string // task id
	Ecosystem     string // "pypi" | "maven" | "npm" — reported separately (the paper finds per-language variance)
	Repo          string // source repository
	TargetVersion string // the historical release the fix must be ported to
	// Image is the task's Dockerized environment; TestCmd is the command whose
	// exit status is the oracle.
	Image   string
	TestCmd []string
}

// BackportSolver is the system under test: given a task, produce the backported
// file contents (path → lines). Returning ok=false is an honest DECLINE (e.g.
// our own layer said needs_adaptation and no adapter was wired) — scored as
// unresolved, never as an error.
type BackportSolver func(ctx context.Context, inst BackportInstance) (files map[string][]string, ok bool, err error)

// BackportRunner is the EXECUTION oracle: apply files inside the task's
// environment and run its tests. passed reflects the test outcome only.
type BackportRunner func(ctx context.Context, inst BackportInstance, files map[string][]string) (passed bool, output string, err error)

// BackportOutcome is one task's result.
type BackportOutcome struct {
	ID        string
	Ecosystem string
	Resolved  bool   // tests passed after the candidate backport
	Declined  bool   // the solver honestly produced no patch
	Err       string // solver or runner error (counts as unresolved)
	Note      string
}

// BackportReport is the scorecard.
type BackportReport struct {
	Total    int
	Resolved int
	Declined int
	Errors   int
	// ByEcosystem holds resolved/total per ecosystem, because BackportBench
	// reports (and finds meaningful variance) per language.
	ByEcosystem map[string]*BackportEcoScore
	Outcomes    []BackportOutcome
}

// BackportEcoScore is a per-ecosystem tally.
type BackportEcoScore struct {
	Total    int
	Resolved int
}

// ResolveRate is the headline metric: the fraction of tasks whose tests pass
// after the candidate backport. 0 when there are no tasks (never NaN).
func (r *BackportReport) ResolveRate() float64 {
	if r == nil || r.Total == 0 {
		return 0
	}
	return float64(r.Resolved) / float64(r.Total)
}

// Rate is the per-ecosystem resolve rate.
func (s *BackportEcoScore) Rate() float64 {
	if s == nil || s.Total == 0 {
		return 0
	}
	return float64(s.Resolved) / float64(s.Total)
}

// ScoreBackport runs every instance through the solver and grades it with the
// execution runner.
//
// Honest accounting: a decline and an error both count as UNRESOLVED (they are
// not successes), and both are reported separately so a run that mostly errored
// can never be mistaken for a run that mostly failed to fix things. A cancelled
// context stops the sweep and returns what completed — a partial run is
// reported as partial, not padded.
func ScoreBackport(ctx context.Context, instances []BackportInstance, solve BackportSolver, run BackportRunner) *BackportReport {
	rep := &BackportReport{ByEcosystem: map[string]*BackportEcoScore{}}
	for _, inst := range instances {
		if ctx.Err() != nil {
			break
		}
		rep.Total++
		eco := rep.ByEcosystem[inst.Ecosystem]
		if eco == nil {
			eco = &BackportEcoScore{}
			rep.ByEcosystem[inst.Ecosystem] = eco
		}
		eco.Total++

		o := BackportOutcome{ID: inst.ID, Ecosystem: inst.Ecosystem}
		files, ok, err := solve(ctx, inst)
		switch {
		case err != nil:
			o.Err = err.Error()
			rep.Errors++
		case !ok || len(files) == 0:
			o.Declined = true
			o.Note = "solver produced no backport (honest decline)"
			rep.Declined++
		default:
			passed, out, rerr := run(ctx, inst, files)
			if rerr != nil {
				o.Err = rerr.Error()
				rep.Errors++
				break
			}
			o.Resolved = passed
			if passed {
				rep.Resolved++
				eco.Resolved++
				o.Note = "tests passed in the task environment"
			} else {
				o.Note = truncateOut(out)
			}
		}
		rep.Outcomes = append(rep.Outcomes, o)
	}
	return rep
}

// RenderBackport formats the scorecard. It states the comparison honestly: the
// paper's own finding is that agentic methods beat traditional patch-porting
// (especially where the port needs logical/structural change) and that results
// vary by language — so a single number without the per-ecosystem split is
// misleading.
func RenderBackport(r *BackportReport) string {
	if r == nil || r.Total == 0 {
		return "=== BackportBench: no tasks run (dataset not present) ===\n" +
			"The 202-task Dockerized corpus is fetched out of band; without it there is no number.\n"
	}
	s := fmt.Sprintf("=== BackportBench scorecard (%d task(s)) ===\n", r.Total)
	s += fmt.Sprintf("resolve rate:  %.2f%%  (%d/%d tests-passing backports)\n",
		r.ResolveRate()*100, r.Resolved, r.Total)
	s += fmt.Sprintf("declined:      %d (no patch produced)\nerrors:        %d\n", r.Declined, r.Errors)
	ecos := make([]string, 0, len(r.ByEcosystem))
	for k := range r.ByEcosystem {
		ecos = append(ecos, k)
	}
	sort.Strings(ecos)
	s += "per-ecosystem:\n"
	for _, e := range ecos {
		sc := r.ByEcosystem[e]
		s += fmt.Sprintf("  %-8s %5.1f%%  (%d/%d)\n", e, sc.Rate()*100, sc.Resolved, sc.Total)
	}
	s += "oracle: the task's own test suite in its Docker environment — a backport\n" +
		"  counts only when the tests pass. Verdicts from internal/backport are a\n" +
		"  safety layer, never evidence of correctness.\n" +
		"citation: BackportBench, arXiv 2512.01396 (202 tasks, 12 repos, PyPI/Maven/npm).\n"
	return s
}

func truncateOut(s string) string {
	const max = 200
	if len(s) <= max {
		return s
	}
	return s[:max] + "…"
}
