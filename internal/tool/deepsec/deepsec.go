// Package deepsec wraps vercel-labs/deepsec (Apache-2.0) — an agent-driven source-code reviewer: a
// regex pass picks candidate files, then a coding agent (OpenAI Codex here) investigates each one and
// reports vulnerabilities with line numbers and a recommendation. Registered via init().
//
// WHY A WRAPPER AND NOT codesweep. §13 says wrap the leading OSS tool. deepsec does the job codesweep
// does — LLM discovery over source — with a stronger shape (an agent that can read across files,
// resumable, incremental) and a public following. Wrapping it is the §13 answer; extending an in-house
// sweep to match it would be the in-house engine §13 forbids.
//
// WHERE IT SITS. The repository asset's REGISTRY tier, never an anchor: its own docs put a 2,000-file
// review at $500–1,200 on a frontier model, so it runs only when someone asks for it (the replay API,
// the L2 Lead's dispatch_l2_probe, an explicit registry opt-in). And what it reports is one model's
// reading of the code, so its findings land as pattern_match and nothing here marks them verified.
// DeepSecBench — Vercel's own benchmark of this harness — puts the best model at ~36% recall on known
// issues; a clean deepsec run is therefore NOT evidence the code is clean, and the coverage note this
// wrapper emits on a partial run exists so a capped review never reads as a complete one.
//
// FOUR RULES THIS WRAPPER ENFORCES, each learned from running the tool:
//
//  1. A COST CAP IS REQUIRED, and enforced HERE. deepsec's `process` command has no cost flag (only
//     `init`/`setup` do, and both want a Vercel project link). So the wrapper processes in small waves
//     and reads the recorded cost after each one, stopping when the cap is reached. Overshoot is
//     bounded by ONE wave, which is stated rather than hidden.
//  2. THE CHILD GETS A CLEAN ENVIRONMENT. Run on a developer machine, deepsec silently used that
//     machine's logged-in `codex` CLI and billed it. In a sandbox the analogue is worse: inherited cloud
//     credentials, a gateway token, someone else's login. The child sees PATH, a throwaway HOME and
//     CODEX_HOME, and the one key it was given — nothing else from the sandbox environment.
//  3. THE KEY NEVER LEAVES THE PROCESS ENVIRONMENT. It arrives as the internal `_api_key` arg (set by
//     the platform from the tenant's own sealed key, never by a caller), goes into the child's env, and
//     appears in no finding, no ToolArgs, no error string.
//  4. A PARTIAL REVIEW SAYS SO. Budget exhausted, a wave failed, or the deadline hit with candidates
//     still pending → one INFORMATIONAL coverage:: finding naming how many candidate files were not
//     reviewed and why. Rendered as nothing, a capped review is indistinguishable from a clean one.
package deepsec

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/ClatTribe/tsengine/internal/tool"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// Version is the deepsec release the sandbox image installs. Bump both together.
const Version = "2.3.10"

// DefaultWorkspace is where the image installs deepsec and its node_modules.
const DefaultWorkspace = "/opt/deepsec"

// DefaultModel is deepsec's own default for the codex backend.
const DefaultModel = "gpt-5.5"

// MaxCostCeiling is a sanity bound on a single run. The platform clamps tighter (to the tenant's
// remaining monthly budget); this only stops an obviously mistyped value.
const MaxCostCeiling = 1000.0

// waveSize is how many candidate files one `process` invocation may take. Small on purpose: the cost cap
// is checked between waves, so the wave is the overshoot bound.
const waveSize = 5

// projectID is the fixed id the per-run workspace registers the target under.
const projectID = "target"

// runner executes one deepsec CLI invocation. Swappable so tests never spawn node.
type runner func(ctx context.Context, dir string, env []string, args ...string) ([]byte, error)

// Deepsec is the tool.Tool implementation.
type Deepsec struct {
	Workspace string // template workspace with node_modules; default DefaultWorkspace
	run       runner
}

// New constructs the wrapper.
func New() *Deepsec { return &Deepsec{Workspace: DefaultWorkspace} }

func (*Deepsec) Name() string           { return "deepsec" }
func (*Deepsec) SandboxExecution() bool { return true }

// MITRETechniques: discovery over source ahead of exploitation of a public-facing application.
func (*Deepsec) MITRETechniques() []string { return []string{"T1190"} }

// KnownArgs declares the recognized arg keys (tool.ArgSpec). `_api_key` is internal: the platform sets
// it from the tenant's sealed key and strips any value a caller supplied.
func (*Deepsec) KnownArgs() []string {
	return []string{"target", "max_cost_usd", "model", "_api_key"}
}

// Output is the run summary carried in tool.Result.Output, so the platform can meter the spend and the
// engineer can see how much of the candidate set was actually reviewed.
type Output struct {
	Model          string  `json:"model"`
	CostUSD        float64 `json:"cost_usd"`
	CostKnown      bool    `json:"cost_known"`
	MaxCostUSD     float64 `json:"max_cost_usd"`
	CandidateFiles int     `json:"candidate_files"`
	ReviewedFiles  int     `json:"reviewed_files"`
	PendingFiles   int     `json:"pending_files"`
	StoppedReason  string  `json:"stopped_reason"` // complete | budget | wave_failed | deadline
	Waves          int     `json:"waves"`
}

func (d *Deepsec) exec() runner {
	if d.run != nil {
		return d.run
	}
	return func(ctx context.Context, dir string, env []string, args ...string) ([]byte, error) {
		// Resolved on PATH (the image links /usr/local/bin/deepsec to the installed CLI). The workspace's
		// node_modules symlink is what lets its deepsec.config.ts import "deepsec/config".
		cmd := exec.CommandContext(ctx, "deepsec", args...)
		cmd.Dir = dir
		cmd.Env = env
		return cmd.Output()
	}
}

// Run reviews the repository at args["target"].
func (d *Deepsec) Run(ctx context.Context, args tool.Args) (tool.Result, error) {
	target, _ := args["target"].(string)
	target = strings.TrimSpace(strings.TrimPrefix(target, "dir:"))
	if target == "" {
		return tool.Result{}, errors.New("deepsec: missing required arg 'target' (the repository path)")
	}
	key, _ := args["_api_key"].(string)
	if strings.TrimSpace(key) == "" {
		// Refused, never defaulted to an ambient credential — see rule 2.
		return tool.Result{}, errors.New("deepsec: no model key was provided; deepsec runs only on the tenant's own OpenAI key")
	}
	maxCost, ok := argFloat(args["max_cost_usd"])
	if !ok || maxCost <= 0 {
		return tool.Result{}, errors.New("deepsec: max_cost_usd is required and must be positive — a review with no spending cap is not run")
	}
	if maxCost > MaxCostCeiling {
		return tool.Result{}, fmt.Errorf("deepsec: max_cost_usd %.2f exceeds the %.0f ceiling for one run", maxCost, MaxCostCeiling)
	}
	model, _ := args["model"].(string)
	if model = strings.TrimSpace(model); model == "" {
		model = DefaultModel
	}
	abs, err := filepath.Abs(target)
	if err != nil {
		return tool.Result{}, fmt.Errorf("deepsec: target: %w", err)
	}

	ws, env, cleanup, err := d.prepare(abs, key)
	if err != nil {
		return tool.Result{}, err
	}
	defer cleanup()
	run := d.exec()

	if so, err := run(ctx, ws, env, "scan", "--project-id", projectID); err != nil {
		// No exit code means "found something" for scan: any non-zero is the tool failing to look.
		if tool.Failed(err) {
			return tool.Result{}, fmt.Errorf("deepsec scan: %s", detail(err, so, key))
		}
	}

	out := Output{Model: model, MaxCostUSD: maxCost, StoppedReason: "complete"}
	for {
		st, rerr := readState(ws)
		if rerr != nil {
			return tool.Result{}, fmt.Errorf("deepsec: read results: %w", rerr)
		}
		out.CostUSD, out.CostKnown = st.cost, st.costKnown
		out.CandidateFiles, out.ReviewedFiles, out.PendingFiles = st.candidates, st.reviewed, st.pending
		if st.pending == 0 {
			break
		}
		if st.cost >= maxCost {
			out.StoppedReason = "budget"
			break
		}
		if ctx.Err() != nil {
			out.StoppedReason = "deadline"
			break
		}
		po, perr := run(ctx, ws, env, "process", "--project-id", projectID,
			"--agent", "codex", "--model", model,
			"--limit", strconv.Itoa(waveSize), "--batch-size", strconv.Itoa(waveSize), "--concurrency", "1")
		out.Waves++
		if perr != nil && tool.Failed(perr) {
			if out.Waves == 1 && st.reviewed == 0 {
				// The first wave failed and nothing was reviewed: the tool did not look at all, and the pass
				// must degrade loudly rather than return an empty list.
				return tool.Result{}, fmt.Errorf("deepsec process: %s", detail(perr, po, key))
			}
			out.StoppedReason = "wave_failed"
			if st2, e2 := readState(ws); e2 == nil {
				out.CostUSD, out.CostKnown = st2.cost, st2.costKnown
				out.CandidateFiles, out.ReviewedFiles, out.PendingFiles = st2.candidates, st2.reviewed, st2.pending
			}
			break
		}
		// A wave that reviewed nothing new would loop forever; treat it as a failed wave.
		if after, e2 := readState(ws); e2 == nil && after.pending >= st.pending {
			out.StoppedReason = "wave_failed"
			out.CostUSD, out.CostKnown = after.cost, after.costKnown
			out.CandidateFiles, out.ReviewedFiles, out.PendingFiles = after.candidates, after.reviewed, after.pending
			break
		}
	}

	st, err := readState(ws)
	if err != nil {
		return tool.Result{}, fmt.Errorf("deepsec: read results: %w", err)
	}
	findings := st.findings
	if out.PendingFiles > 0 {
		findings = append(findings, coverageFinding(out))
	}
	return tool.Result{Findings: findings, Output: out}, nil
}

// prepare builds a throwaway workspace that registers ONLY this target, sharing the image's
// node_modules, and the clean child environment.
func (d *Deepsec) prepare(target, key string) (string, []string, func(), error) {
	tmpl := d.Workspace
	if tmpl == "" {
		tmpl = DefaultWorkspace
	}
	ws, err := os.MkdirTemp("", "deepsec-ws-")
	if err != nil {
		return "", nil, func() {}, err
	}
	cleanup := func() { _ = os.RemoveAll(ws) }
	fail := func(e error) (string, []string, func(), error) { cleanup(); return "", nil, func() {}, e }

	if err := os.Symlink(filepath.Join(tmpl, "node_modules"), filepath.Join(ws, "node_modules")); err != nil {
		return fail(fmt.Errorf("deepsec: workspace: %w", err))
	}
	pkg := fmt.Sprintf(`{"name":"deepsec-run","private":true,"type":"module","dependencies":{"deepsec":%q}}`, Version)
	cfg := fmt.Sprintf("import { defineConfig } from \"deepsec/config\";\n\nexport default defineConfig({\n  projects: [{ id: %q, root: %q }],\n});\n",
		projectID, target)
	files := map[string]string{
		"package.json":      pkg,
		"deepsec.config.ts": cfg,
		filepath.Join("data", projectID, "INFO.md"): "# target\n\nRepository under review by TensorShield. No additional context supplied.\n",
	}
	for name, body := range files {
		p := filepath.Join(ws, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			return fail(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			return fail(err)
		}
	}
	home := filepath.Join(ws, ".home")
	codexHome := filepath.Join(ws, ".codex")
	for _, p := range []string{home, codexHome} {
		if err := os.MkdirAll(p, 0o700); err != nil {
			return fail(err)
		}
	}
	return ws, childEnv(home, codexHome, key), cleanup, nil
}

// childEnv is the WHOLE environment the deepsec process sees — built from nothing, not filtered from
// os.Environ(), because a deny-list misses whatever variable someone adds next.
func childEnv(home, codexHome, key string) []string {
	path := os.Getenv("PATH")
	if path == "" {
		path = "/usr/local/bin:/usr/bin:/bin"
	}
	return []string{
		"PATH=" + path,
		"HOME=" + home,
		"CODEX_HOME=" + codexHome,
		"OPENAI_API_KEY=" + key,
		"NO_COLOR=1",
		"CI=1", // deepsec's TUI and prompts stay off without a TTY; CI makes it explicit
	}
}

// --- results ---

type fileRecord struct {
	FilePath   string            `json:"filePath"`
	Status     string            `json:"status"`
	Candidates []json.RawMessage `json:"candidates"`
	Findings   []struct {
		Severity       string `json:"severity"`
		VulnSlug       string `json:"vulnSlug"`
		Title          string `json:"title"`
		Description    string `json:"description"`
		LineNumbers    []int  `json:"lineNumbers"`
		Recommendation string `json:"recommendation"`
		Confidence     string `json:"confidence"`
		FindingID      string `json:"findingId"`
	} `json:"findings"`
	AnalysisHistory []struct {
		CostUSD *float64 `json:"costUsd"`
		Model   string   `json:"model"`
	} `json:"analysisHistory"`
}

type state struct {
	candidates, reviewed, pending int
	cost                          float64
	costKnown                     bool
	findings                      []types.SandboxEmittedFinding
}

func readState(ws string) (state, error) {
	var st state
	root := filepath.Join(ws, "data", projectID, "files")
	var paths []string
	err := filepath.WalkDir(root, func(p string, de os.DirEntry, err error) error {
		if err != nil {
			if os.IsNotExist(err) {
				return filepath.SkipAll
			}
			return err
		}
		if !de.IsDir() && strings.HasSuffix(p, ".json") {
			paths = append(paths, p)
		}
		return nil
	})
	if err != nil {
		return st, err
	}
	sort.Strings(paths) // deterministic finding order
	for _, p := range paths {
		raw, err := os.ReadFile(p)
		if err != nil {
			return st, err
		}
		var rec fileRecord
		if err := json.Unmarshal(raw, &rec); err != nil {
			return st, fmt.Errorf("%s: %w", filepath.Base(p), err)
		}
		if len(rec.Candidates) > 0 {
			st.candidates++
			// Anything not "analyzed" is unreviewed: "pending" never ran, "error" is a batch the agent
			// failed (deepsec retries it next run), "processing" was cut off. Counting only "pending" would
			// let a failed batch vanish from the coverage note — reviewed by nobody, reported by nobody.
			if rec.Status != "analyzed" {
				st.pending++
			}
		}
		if len(rec.AnalysisHistory) > 0 {
			st.reviewed++
		}
		for _, a := range rec.AnalysisHistory {
			if a.CostUSD != nil {
				st.cost += *a.CostUSD
				st.costKnown = true
			}
		}
		for _, f := range rec.Findings {
			st.findings = append(st.findings, toFinding(rec.FilePath, f.Severity, f.VulnSlug, f.Title,
				f.Description, f.Recommendation, f.Confidence, f.FindingID, f.LineNumbers))
		}
	}
	return st, nil
}

// slugCWE maps deepsec's vulnerability slugs to a CWE where the class is unambiguous, so a finding
// reaches the compliance crosswalk. A slug not listed gets no CWE rather than a guessed one.
var slugCWE = map[string]string{
	"sql-injection": "CWE-89", "js-sql-raw": "CWE-89",
	"xss": "CWE-79", "dangerous-html": "CWE-79", "unsafe-json-in-html": "CWE-79",
	"rce":  "CWE-78",
	"ssrf": "CWE-918", "framework-untrusted-fetch": "CWE-918",
	"path-traversal": "CWE-22",
	"open-redirect":  "CWE-601", "unsafe-redirect": "CWE-601",
	"missing-auth":     "CWE-306",
	"auth-bypass":      "CWE-287",
	"secrets-exposure": "CWE-798", "secret-in-fallback": "CWE-798",
	"secret-in-log":          "CWE-532",
	"insecure-crypto":        "CWE-327",
	"unsafe-deserialization": "CWE-502",
	"cors-wildcard":          "CWE-942",
	"jwt-handling":           "CWE-347",
	"algorithm-confusion":    "CWE-347",
	"cross-tenant-id":        "CWE-639",
	"non-atomic-read-delete": "CWE-367",
	"non-atomic-operation":   "CWE-367",
}

func toFinding(path, sev, slug, title, desc, rec, conf, id string, lines []int) types.SandboxEmittedFinding {
	endpoint := path
	if len(lines) > 0 {
		endpoint = fmt.Sprintf("%s:%d", path, lines[0])
	}
	if slug == "" {
		slug = "other"
	}
	var cwe []string
	if c, ok := slugCWE[slug]; ok {
		cwe = []string{c}
	}
	body := desc
	if rec != "" {
		body += "\n\nRecommendation (deepsec): " + rec
	}
	lineStrs := make([]string, 0, len(lines))
	for _, l := range lines {
		lineStrs = append(lineStrs, strconv.Itoa(l))
	}
	return types.SandboxEmittedFinding{
		RuleID:      "deepsec::" + slug,
		Tool:        "deepsec",
		Severity:    normSeverity(sev),
		CWE:         cwe,
		Endpoint:    endpoint,
		Title:       title,
		Description: body,
		RawOutput: mustJSON(map[string]any{
			"deepsec_finding_id": id, "severity": sev, "confidence": conf, "line_numbers": lines,
			"note": "one model's reading of the source; not exploited, not verified",
		}),
		ToolArgs: map[string]string{"file": path, "lines": strings.Join(lineStrs, ","), "slug": slug, "confidence": conf},
	}
}

// normSeverity maps deepsec's labels onto ours. "BUG" (a defect that is not a vulnerability) and any
// label we do not recognise become info — reported, never inflated.
func normSeverity(s string) types.Severity {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "CRITICAL":
		return types.SeverityCritical
	case "HIGH":
		return types.SeverityHigh
	case "MEDIUM":
		return types.SeverityMedium
	case "LOW":
		return types.SeverityLow
	default:
		return types.SeverityInfo
	}
}

func mustJSON(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}

// coverageRulePrefix must equal asset.CoverageRulePrefix (asserted by test; not imported, because the
// asset package imports tool and a wrapper importing asset would invert the dependency).
const coverageRulePrefix = "coverage::"

func coverageFinding(o Output) types.SandboxEmittedFinding {
	why := map[string]string{
		"budget":      fmt.Sprintf("the $%.2f spending cap was reached ($%.2f spent)", o.MaxCostUSD, o.CostUSD),
		"wave_failed": "an AI review wave failed partway through",
		"deadline":    "the run's deadline was reached",
	}[o.StoppedReason]
	if why == "" {
		why = "the review stopped early"
	}
	return types.SandboxEmittedFinding{
		RuleID:   coverageRulePrefix + "deepsec-incomplete",
		Tool:     "deepsec",
		Severity: types.SeverityInfo,
		Endpoint: "repository",
		Title: fmt.Sprintf("AI code review incomplete: %d of %d candidate files were not reviewed",
			o.PendingFiles, o.CandidateFiles),
		Description: fmt.Sprintf("deepsec stopped because %s. %d candidate files were reviewed and %d were not. "+
			"This is NOT a vulnerability and NOT a clean result for the unreviewed files: nobody looked at them. "+
			"Re-run with a higher max_cost_usd to review the rest; files already reviewed are not re-billed.",
			why, o.ReviewedFiles, o.PendingFiles),
		RawOutput: mustJSON(map[string]any{"stopped_reason": o.StoppedReason, "pending_files": o.PendingFiles,
			"reviewed_files": o.ReviewedFiles, "cost_usd": o.CostUSD, "max_cost_usd": o.MaxCostUSD}),
	}
}

// scrub removes the key from any text bound for an error message. Belt and braces: deepsec should never
// print it, but an error string is persisted in ToolsFailed and shown to people.
func scrub(s, key string) string {
	if key == "" {
		return s
	}
	return strings.ReplaceAll(s, key, "[redacted]")
}

var ansi = regexp.MustCompile(`\x1b\[[0-9;]*m`)

// detail renders a failed invocation. deepsec reports most failures on STDOUT (it is a line-oriented
// CLI without a TTY), so stderr alone — which is all tool.ExitDetail sees — usually says only "exit
// status 1". The stdout tail carries the reason (a quota stop, a rejected key).
func detail(err error, stdout []byte, key string) string {
	d := tool.ExitDetail(err)
	if tail := strings.TrimSpace(ansi.ReplaceAllString(string(stdout), "")); tail != "" {
		if len(tail) > 400 {
			tail = "…" + tail[len(tail)-400:]
		}
		d += ": " + strings.ReplaceAll(tail, "\n", " · ")
	}
	return scrub(d, key)
}

func argFloat(v any) (float64, bool) {
	switch x := v.(type) {
	case float64:
		return x, true
	case int:
		return float64(x), true
	case string:
		f, err := strconv.ParseFloat(strings.TrimSpace(x), 64)
		return f, err == nil
	case json.Number:
		f, err := x.Float64()
		return f, err == nil
	}
	return 0, false
}

func init() { tool.Register(New()) }
