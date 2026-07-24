package codelocalize

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// llm.go is the "D-agent" tier for localization, the direct analog of pentest/llmspec.go. The model
// PROPOSES which files are the likely sink for the vuln class (widening recall to sinks/idioms the
// deterministic token table can't see); a deterministic predicate DISPOSES every proposal — a proposed
// path must EXIST in the repo AND carry some real security-relevant evidence (a taint source, a query
// keyword, or ANY sink token) — so the model can never invent a clean file as a finding (no LLM false
// positives, §10). The final ranking puts groundable model picks first, then appends any heuristic
// candidates the model missed, so LLMLocalizer is MONOTONICALLY ≥ the heuristic in recall — it can only
// reorder-up and add, never drop a heuristic hit.

// LLM is the minimal text-in/text-out seam. cloudengine.LLM satisfies it structurally, so a local
// Ollama (via cloudengine.LLMFromEnv) or a per-tenant frontier key drives the localizer for free.
type LLM interface {
	Generate(ctx context.Context, prompt string) (string, error)
}

// LLMLocalizer wraps a model with the deterministic grounder + heuristic fallback.
type LLMLocalizer struct {
	LLM LLM
}

// Localize runs the heuristic (always — it's the floor + the fallback), then asks the model to rank,
// grounds each proposal, and merges. A nil/erroring model or an ungroundable proposal set degrades to
// the pure heuristic result (never a falsely-confident LLM-only ranking).
func (l LLMLocalizer) Localize(ctx context.Context, q Query, repo Repo) (Result, error) {
	base, err := HeuristicLocalizer{}.Localize(ctx, q, repo)
	if err != nil {
		return base, err
	}
	if l.LLM == nil {
		return base, nil
	}
	out, err := l.LLM.Generate(ctx, localizePrompt(q, repo))
	if err != nil {
		base.Trace = append(base.Trace, fmt.Sprintf("model unavailable (%v) — heuristic ranking stands", err))
		return base, nil
	}
	proposed := parseProposals(out)
	if len(proposed) == 0 {
		base.Trace = append(base.Trace, "model returned no parseable proposal — heuristic ranking stands")
		return base, nil
	}

	byPath := repo.index()
	baseByPath := map[string]Candidate{}
	for _, c := range base.Ranked {
		baseByPath[c.Path] = c
	}

	var merged []Candidate
	kept := map[string]bool{}
	grounded, dropped := 0, 0
	for _, p := range proposed {
		f, ok := byPath[p.Path]
		if !ok || kept[p.Path] {
			dropped++
			continue
		}
		if !groundableForLLM(f, q) {
			dropped++
			continue // model proposed a file with no security-relevant evidence — refuse it (§10)
		}
		grounded++
		kept[p.Path] = true
		// keep the heuristic's evidence/score if we have it; otherwise synthesize a grounded reason.
		if hc, ok := baseByPath[p.Path]; ok {
			merged = append(merged, hc)
		} else {
			merged = append(merged, Candidate{
				Path:    p.Path,
				Score:   wStrongSink, // a grounded model pick ranks alongside a strong sink
				Reasons: []string{fmt.Sprintf("model-proposed sink (grounded): %s", strings.TrimSpace(p.Why))},
			})
		}
	}
	// append heuristic candidates the model didn't name — recall floor preserved.
	for _, c := range base.Ranked {
		if !kept[c.Path] {
			merged = append(merged, c)
		}
	}

	res := Result{Ranked: merged, Engine: "llm+heuristic"}
	res.Trace = append(res.Trace, base.Trace...)
	res.Trace = append(res.Trace, fmt.Sprintf("model proposed %d files: %d grounded+kept, %d dropped as ungroundable/unknown", len(proposed), grounded, dropped))
	return res, nil
}

// index maps repo paths to files for O(1) grounding lookups.
func (r Repo) index() map[string]File {
	m := make(map[string]File, len(r))
	for _, f := range r {
		m[f.Path] = f
	}
	return m
}

// allSinkTokens is every strong+weak token across the whole table — the broad "is this security-relevant
// code at all?" gate the LLM grounder uses (broader than one CWE's list, so the model can widen recall,
// but still a real-evidence gate, not a blank check).
var allSinkTokens = func() []string {
	var out []string
	for _, sig := range sinkTable {
		out = append(out, sig.strong...)
		out = append(out, sig.weak...)
	}
	sort.Strings(out)
	return out
}()

// groundableForLLM is the disposer: a model-proposed file is acceptable only if it carries a taint
// source, a query keyword, or ANY sink token. A file of pure clean code is refused.
func groundableForLLM(f File, q Query) bool {
	low := strings.ToLower(f.Content)
	for _, s := range sourceTokens {
		if strings.Contains(low, s) {
			return true
		}
	}
	for _, k := range q.keywords() {
		if strings.Contains(low, k) {
			return true
		}
	}
	for _, t := range allSinkTokens {
		if strings.Contains(low, t) {
			return true
		}
	}
	return false
}

type proposal struct {
	Path string `json:"path"`
	Why  string `json:"why"`
}

// parseProposals extracts the model's JSON array of {path, why}, tolerating prose/markdown fences around
// it (models wrap JSON). Returns nil on anything unparseable — the caller then keeps the heuristic.
func parseProposals(s string) []proposal {
	start := strings.Index(s, "[")
	end := strings.LastIndex(s, "]")
	if start < 0 || end <= start {
		return nil
	}
	var ps []proposal
	if err := json.Unmarshal([]byte(s[start:end+1]), &ps); err != nil {
		return nil
	}
	var out []proposal
	for _, p := range ps {
		if p.Path = strings.TrimSpace(p.Path); p.Path != "" {
			out = append(out, p)
		}
	}
	return out
}

// localizePrompt asks the model to rank candidate files for the vuln class. It provides the file list
// (with a first-sink hint where the heuristic saw one) so the model reasons over the real surface, and
// constrains output to a compact JSON array. Capped so a huge repo can't blow the context.
func localizePrompt(q Query, repo Repo) string {
	var b strings.Builder
	b.WriteString("You are a security code auditor localizing a vulnerability. Identify which source files most likely contain the SINK for this issue.\n\n")
	fmt.Fprintf(&b, "CWE: %s\nTitle: %s\nDescription: %s\n\n", strings.Join(q.CWE, ", "), q.Title, q.Description)
	b.WriteString("Candidate files (path — hint):\n")
	const maxFiles = 60
	for i, f := range repo {
		if i >= maxFiles {
			fmt.Fprintf(&b, "... (%d more files omitted)\n", len(repo)-maxFiles)
			break
		}
		fmt.Fprintf(&b, "- %s — %s\n", f.Path, firstSinkHint(f))
	}
	b.WriteString("\nReturn ONLY a JSON array of the up-to-8 most likely files, most-likely first: ")
	b.WriteString(`[{"path":"<exact path from the list>","why":"<one line>"}]. Use only paths from the list.`)
	return b.String()
}

// firstSinkHint returns a short hint (the first line containing any sink token) to orient the model,
// or a size note if none. Purely advisory — the grounder, not the hint, decides acceptance.
func firstSinkHint(f File) string {
	for _, raw := range strings.Split(f.Content, "\n") {
		low := strings.ToLower(raw)
		for _, t := range allSinkTokens {
			if strings.Contains(low, t) {
				h := strings.TrimSpace(raw)
				if len(h) > 80 {
					h = h[:80]
				}
				return h
			}
		}
	}
	return fmt.Sprintf("%d bytes, no obvious sink token", len(f.Content))
}
