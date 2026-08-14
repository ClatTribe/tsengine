// Package codesweep is FOCUSED-TASK vulnerability discovery over a repository: decompose the search
// into many small, well-defined questions, answer them in parallel, then deduplicate and rank.
//
// WHY, and what it changes. codeagent.Investigate points ONE agent at the whole repo with a shared
// tool-call budget (MaxIters, default 24). That agent must decide what to look at, and everything it
// spends orienting is budget it does not spend reasoning — so a large repo gets a shallow pass, and
// coverage depends on whatever the model chose to open first. It is also purely REACTIVE: it triages
// findings a scanner already reported, so a vulnerability no scanner flagged is invisible to it.
//
// codesweep inverts that. codelocalize already answers "for CWE-89, which files hold the sink?" — so
// each (CWE, file) pair IS a focused task, with the sink lines attached. One small prompt per task,
// run concurrently, is both cheaper per question and better covered than one agent rationing 24 turns
// across everything. The design is the one open·kritt (github.com/Kritt-ai/open-kritt) argues for;
// only the idea is borrowed — that project is AGPL and none of its code is used here.
//
// This is DISCOVERY, not triage: tasks are generated from the code itself, so it surfaces classes no
// scanner reported. It complements codeagent rather than replacing it — the deep ReAct agent is still
// the right tool for "is this specific finding exploitable, and what is its blast radius?".
//
// GROUNDED (§10). The model proposes; a deterministic disposer decides. A candidate survives only if
// every location it cites is a real line in the file the task actually supplied. A model that invents
// a file, a line past EOF, or a location in a file it was never shown is refused — not downgraded.
// So parallelism widens the search without widening the false-positive surface.
//
// DETERMINISTIC (§10). Tasks are planned and results ordered by content, never by completion order,
// so the same repo yields the same report on every run despite concurrent execution.
package codesweep

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/ClatTribe/tsengine/internal/codelocalize"
)

// LLM is the minimal text-in/text-out seam (cloudengine.LLM satisfies it structurally), so a local
// Ollama or a per-tenant key drives the sweep with no extra wiring.
type LLM interface {
	Generate(ctx context.Context, prompt string) (string, error)
}

// Task is ONE focused question: "is there a <CWE> in <Path>?", with the evidence that made the file a
// candidate. Small and self-contained by design — that is what makes it cheap, parallel, and gradeable.
type Task struct {
	CWE        string   `json:"cwe"`
	Path       string   `json:"path"`
	Reasons    []string `json:"reasons,omitempty"`    // why localize ranked this file (file:line matched <token>)
	SinkLines  []int    `json:"sink_lines,omitempty"` // the lines to look at first
	Confidence float64  `json:"confidence"`           // localize's 0-1 prior
}

// Candidate is a surviving, grounded answer to one Task.
type Candidate struct {
	Task
	Vulnerable bool     `json:"vulnerable"`
	Severity   string   `json:"severity,omitempty"` // critical|high|medium|low|info
	Title      string   `json:"title,omitempty"`
	Rationale  string   `json:"rationale,omitempty"`
	Evidence   []string `json:"evidence,omitempty"` // "path:line" locations, each verified to exist
}

// Result is one sweep.
type Result struct {
	Candidates []Candidate `json:"candidates"`
	Planned    int         `json:"planned"` // tasks the plan produced
	Ran        int         `json:"ran"`     // tasks actually executed (may be < planned when capped)
	Refused    int         `json:"refused"` // proposals the disposer rejected as ungrounded
	Failed     int         `json:"failed"`  // tasks whose model call or parse failed
}

// Coverage reports the fraction of planned tasks that actually ran. Surfaced so a capped sweep is
// never mistaken for an exhaustive one.
func (r Result) Coverage() float64 {
	if r.Planned == 0 {
		return 0
	}
	return float64(r.Ran) / float64(r.Planned)
}

// PlanOptions bound the decomposition.
type PlanOptions struct {
	// CWEs to hunt. Empty → every class codelocalize can localize (the full sink table).
	CWEs []string
	// MaxFilesPerCWE keeps one noisy class from consuming the whole budget (default 5).
	MaxFilesPerCWE int
	// MinConfidence drops weak candidates before they cost a model call (default 0 — keep all).
	MinConfidence float64
	// MaxTasks caps the whole plan (default 200). A cap is REPORTED, never silent.
	MaxTasks int
	// IncludeTests plans tasks against test files too. Default FALSE: a weakness in a test does not
	// ship, so those are wasted model calls — and they are numerous (running this over a real package
	// planned most of its tasks against _test files, which is how this option came to exist). Set true
	// when auditing the test suite itself.
	IncludeTests bool
}

// isTestPath reports whether a path is test-only code across the languages codelocalize scans.
func isTestPath(p string) bool {
	base := p
	if i := strings.LastIndex(p, "/"); i >= 0 {
		base = p[i+1:]
	}
	low := strings.ToLower(base)
	switch {
	case strings.HasSuffix(low, "_test.go"), strings.HasSuffix(low, ".test.js"), strings.HasSuffix(low, ".test.ts"),
		strings.HasSuffix(low, ".spec.js"), strings.HasSuffix(low, ".spec.ts"), strings.HasSuffix(low, "_test.py"),
		strings.HasPrefix(low, "test_"), strings.HasSuffix(low, "test.java"):
		return true
	}
	// A path segment that is a conventional test directory.
	for _, seg := range strings.Split(strings.ToLower(p), "/") {
		if seg == "test" || seg == "tests" || seg == "spec" || seg == "__tests__" || seg == "testdata" {
			return true
		}
	}
	return false
}

func (o PlanOptions) withDefaults() PlanOptions {
	if o.MaxFilesPerCWE <= 0 {
		o.MaxFilesPerCWE = 5
	}
	if o.MaxTasks <= 0 {
		o.MaxTasks = 200
	}
	if len(o.CWEs) == 0 {
		o.CWEs = codelocalize.LocalizableCWEs()
	}
	return o
}

// Plan decomposes a repository into focused tasks by localizing each CWE class and taking its
// top-ranked files. This is the whole trick: the expensive "where should I even look?" question is
// answered DETERMINISTICALLY and for free, so every model call starts already pointed at a sink.
func Plan(ctx context.Context, loc codelocalize.Localizer, repo codelocalize.Repo, opts PlanOptions) ([]Task, error) {
	opts = opts.withDefaults()
	var tasks []Task

	cwes := append([]string(nil), opts.CWEs...)
	sort.Strings(cwes) // deterministic plan order (§10)

	for _, cwe := range cwes {
		res, err := loc.Localize(ctx, codelocalize.Query{CWE: []string{cwe}}, repo)
		if err != nil {
			return nil, fmt.Errorf("codesweep: localize %s: %w", cwe, err)
		}
		n := 0
		for _, c := range res.Ranked {
			if n >= opts.MaxFilesPerCWE {
				break
			}
			if c.Confidence < opts.MinConfidence {
				continue // too weak to be worth a model call
			}
			if !opts.IncludeTests && isTestPath(c.Path) {
				continue // a weakness in a test does not ship
			}
			tasks = append(tasks, Task{
				CWE: cwe, Path: c.Path, Reasons: c.Reasons,
				SinkLines: c.SinkLines, Confidence: c.Confidence,
			})
			n++
		}
	}

	// Strongest priors first, so a truncating cap keeps the best tasks rather than an arbitrary slice.
	sort.SliceStable(tasks, func(i, j int) bool {
		if tasks[i].Confidence != tasks[j].Confidence {
			return tasks[i].Confidence > tasks[j].Confidence
		}
		if tasks[i].CWE != tasks[j].CWE {
			return tasks[i].CWE < tasks[j].CWE
		}
		return tasks[i].Path < tasks[j].Path
	})
	if len(tasks) > opts.MaxTasks {
		tasks = tasks[:opts.MaxTasks]
	}
	return tasks, nil
}

// SweepOptions bound execution.
type SweepOptions struct {
	// Concurrency is how many tasks run at once (default 4, matching TSENGINE_DISPATCH_CONCURRENCY).
	Concurrency int
	// MaxExcerptLines caps how much of a file is sent per task (default 400). A focused task should
	// carry a focused excerpt — sending whole large files is the cost blow-up this design avoids.
	MaxExcerptLines int
}

func (o SweepOptions) withDefaults() SweepOptions {
	if o.Concurrency <= 0 {
		o.Concurrency = 4
	}
	if o.MaxExcerptLines <= 0 {
		o.MaxExcerptLines = 400
	}
	return o
}

// Sweep runs tasks concurrently and returns the grounded, deduplicated, ranked candidates.
//
// A task whose model call or parse fails is COUNTED and skipped — one bad answer must not discard the
// rest of the sweep. A proposal that cites source it was not shown is refused and counted separately,
// because an ungrounded claim is a different (and more interesting) failure than a broken call.
func Sweep(ctx context.Context, llm LLM, repo codelocalize.Repo, tasks []Task, opts SweepOptions) (Result, error) {
	if llm == nil {
		return Result{}, fmt.Errorf("codesweep: no LLM configured — cannot run a sweep")
	}
	opts = opts.withDefaults()
	byPath := repo.Index()

	res := Result{Planned: len(tasks)}
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, opts.Concurrency) // bounded fan-out (§15)

	for _, t := range tasks {
		file, ok := byPath[t.Path]
		if !ok {
			continue // the plan named a file this repo does not have — nothing to ask about
		}
		wg.Add(1)
		go func(t Task, f codelocalize.File) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				return
			}

			out, err := llm.Generate(ctx, buildTaskPrompt(t, f, opts.MaxExcerptLines))
			mu.Lock()
			defer mu.Unlock()
			res.Ran++
			if err != nil {
				res.Failed++
				return
			}
			prop, perr := parseProposal(out)
			if perr != nil {
				res.Failed++
				return
			}
			c, ok := ground(t, f, prop)
			if !ok {
				res.Refused++
				return
			}
			if c.Vulnerable {
				res.Candidates = append(res.Candidates, c)
			}
		}(t, file)
	}
	wg.Wait()

	res.Candidates = dedupe(res.Candidates)
	rank(res.Candidates)
	return res, ctx.Err()
}

// proposal is the model's raw answer, untrusted until ground() disposes of it.
type proposal struct {
	Vulnerable bool     `json:"vulnerable"`
	Severity   string   `json:"severity"`
	Title      string   `json:"title"`
	Rationale  string   `json:"rationale"`
	Evidence   []string `json:"evidence"`
}

// parseProposal extracts the JSON object, tolerating prose or fences around it.
func parseProposal(out string) (proposal, error) {
	start := strings.Index(out, "{")
	end := strings.LastIndex(out, "}")
	if start < 0 || end <= start {
		return proposal{}, fmt.Errorf("no JSON object in model output")
	}
	var p proposal
	if err := json.Unmarshal([]byte(out[start:end+1]), &p); err != nil {
		return proposal{}, err
	}
	return p, nil
}

// severities is the closed set a candidate may claim. An invented severity is normalized rather than
// trusted, so a model cannot escalate by inventing a label.
var severities = map[string]bool{"critical": true, "high": true, "medium": true, "low": true, "info": true}

// ground is the DISPOSER. A proposal survives only if it is about the file it was given and every
// location it cites is a real line in that file.
//
// This is what makes the fan-out safe: N parallel model calls widen the search, but none of them can
// widen what counts as evidence.
func ground(t Task, f codelocalize.File, p proposal) (Candidate, bool) {
	c := Candidate{Task: t, Vulnerable: p.Vulnerable,
		Title: strings.TrimSpace(p.Title), Rationale: strings.TrimSpace(p.Rationale)}

	sev := strings.ToLower(strings.TrimSpace(p.Severity))
	if !severities[sev] {
		sev = "medium" // unknown label → a neutral default, never the model's invented one
	}
	c.Severity = sev

	// A "not vulnerable" answer needs no evidence — it is the absence of a claim.
	if !p.Vulnerable {
		return c, true
	}
	// A POSITIVE claim must be grounded. No citation = no finding (§10).
	if len(p.Evidence) == 0 {
		return c, false
	}
	total := lineCount(f.Content)
	for _, ev := range p.Evidence {
		path, line, ok := splitLocation(ev)
		if !ok || path != t.Path || line < 1 || line > total {
			return c, false // cites another file, a bad format, or a line past EOF
		}
		c.Evidence = append(c.Evidence, fmt.Sprintf("%s:%d", path, line))
	}
	return c, true
}

// splitLocation parses "path:line".
func splitLocation(s string) (string, int, bool) {
	i := strings.LastIndex(s, ":")
	if i <= 0 || i == len(s)-1 {
		return "", 0, false
	}
	n := 0
	for _, r := range s[i+1:] {
		if r < '0' || r > '9' {
			return "", 0, false
		}
		n = n*10 + int(r-'0')
	}
	return strings.TrimSpace(s[:i]), n, true
}

func lineCount(s string) int { return len(strings.Split(s, "\n")) }

// dedupe collapses candidates for the same (path, CWE) — the same weakness found twice is one
// weakness. Keeps the strongest-severity, best-evidenced instance.
func dedupe(in []Candidate) []Candidate {
	best := map[string]Candidate{}
	for _, c := range in {
		k := c.Path + "|" + c.CWE
		prev, seen := best[k]
		if !seen || sevRank(c.Severity) > sevRank(prev.Severity) ||
			(sevRank(c.Severity) == sevRank(prev.Severity) && len(c.Evidence) > len(prev.Evidence)) {
			best[k] = c
		}
	}
	out := make([]Candidate, 0, len(best))
	for _, c := range best {
		out = append(out, c)
	}
	return out
}

func sevRank(s string) int {
	switch s {
	case "critical":
		return 5
	case "high":
		return 4
	case "medium":
		return 3
	case "low":
		return 2
	case "info":
		return 1
	}
	return 0
}

// rank orders candidates severity-desc, then by the localizer's prior, then by path — deterministic
// despite concurrent execution (§10).
func rank(cs []Candidate) {
	sort.SliceStable(cs, func(i, j int) bool {
		if a, b := sevRank(cs[i].Severity), sevRank(cs[j].Severity); a != b {
			return a > b
		}
		if cs[i].Confidence != cs[j].Confidence {
			return cs[i].Confidence > cs[j].Confidence
		}
		if cs[i].Path != cs[j].Path {
			return cs[i].Path < cs[j].Path
		}
		return cs[i].CWE < cs[j].CWE
	})
}

// buildTaskPrompt renders ONE focused question. It hands the model the class, the file, the lines the
// localizer already flagged, and the numbered source — then demands a citation. Numbering the lines
// is what makes the grounding check meaningful: the model cites what it can actually see.
func buildTaskPrompt(t Task, f codelocalize.File, maxLines int) string {
	var b strings.Builder
	fmt.Fprintf(&b, "You are a security researcher auditing ONE file for ONE weakness class.\n\n")
	fmt.Fprintf(&b, "WEAKNESS: %s\nFILE: %s\n", t.CWE, t.Path)
	if len(t.SinkLines) > 0 {
		fmt.Fprintf(&b, "A static pass flagged these lines as candidate sinks: %v\n", t.SinkLines)
	}
	for _, r := range t.Reasons {
		fmt.Fprintf(&b, "  · %s\n", r)
	}
	b.WriteString("\nDecide whether a REAL, reachable instance of this weakness exists here. Attacker-\n")
	b.WriteString("controlled input must actually reach the sink — an unreachable or already-sanitized\n")
	b.WriteString("pattern is NOT a vulnerability. Answering \"no\" is a correct and useful answer.\n\n")
	b.WriteString("SOURCE (line-numbered)\n")
	b.WriteString(numbered(f.Content, maxLines))
	b.WriteString("\nRespond with ONLY a JSON object:\n")
	b.WriteString(`{"vulnerable":true|false,"severity":"critical|high|medium|low|info",` + "\n")
	b.WriteString(` "title":"one line","rationale":"one or two sentences",` + "\n")
	b.WriteString(` "evidence":["` + t.Path + `:<line>", "..."]}` + "\n")
	b.WriteString("Every evidence entry MUST be a line number shown above, in THIS file. A claim citing\n")
	b.WriteString("anything else is discarded.\n")
	return b.String()
}

// numbered renders content with 1-based line numbers, truncated to maxLines. Truncation is stated so
// the model does not reason as if it saw the whole file.
func numbered(content string, maxLines int) string {
	lines := strings.Split(content, "\n")
	var b strings.Builder
	for i, ln := range lines {
		if i >= maxLines {
			fmt.Fprintf(&b, "... (%d more lines not shown)\n", len(lines)-maxLines)
			break
		}
		fmt.Fprintf(&b, "%5d | %s\n", i+1, ln)
	}
	return b.String()
}
