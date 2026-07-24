package toolselect

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// The LLM-assisted refiner: the deterministic BM25 layer (Select) is fast and grounded but purely
// lexical — it can miss a tool whose relevance is semantic, not word-overlap ("the app trusts a
// client-set role" → privesc_probe, with no shared token). The refiner lets a frontier model PROPOSE
// the final active subset from the full eligible candidate list; the deterministic layer then DISPOSES:
//
//   - CLOSED-SET: only names the model returns that are real eligible candidates survive (a
//     hallucinated tool is dropped — the model can never invent a tool, §10).
//   - CAP: always-on CORE tools are prepended and the total is truncated to MaxActive (the model
//     cannot blow the L2-CAP).
//   - FALLBACK: if the model errors or returns nothing usable, we fall back to the BM25 Select — the
//     agent never ends up with an empty or core-only catalog because the LLM hiccuped.
//
// So the model widens/sharpens selection but can never break the two invariants that keep tool-use
// accurate. This mirrors the "model proposes, framework disposes" discipline used everywhere else.

// Generator is the minimal text-in/text-out LLM seam toolselect needs. Any client satisfies it — the
// l2 tool-calling Client via a thin adapter, a local Ollama, or (for e2e validation) a proxy that
// relays to a frontier model. Kept local so toolselect imports no LLM package (no import cycle).
type Generator interface {
	Generate(ctx context.Context, prompt string) (string, error)
}

// GeneratorFunc adapts a plain function to Generator.
type GeneratorFunc func(ctx context.Context, prompt string) (string, error)

func (f GeneratorFunc) Generate(ctx context.Context, prompt string) (string, error) {
	return f(ctx, prompt)
}

// candidate is one selectable tool passed to the model.
type candidate struct {
	Name        string
	Description string
}

// SelectLLM refines the active set with a Generator. It gathers the phase-eligible non-core tools as
// candidates, asks the model to pick the ones relevant to the task, and disposes the answer against
// the closed set + cap. On any model failure it returns the deterministic Select result (fallbackUsed
// true) so the caller always gets a valid, capped selection.
func (c *Catalog) SelectLLM(ctx context.Context, q Query, gen Generator) (sel Selection, fallbackUsed bool) {
	max := q.MaxActive
	if max <= 0 {
		max = DefaultMaxActive
	}

	var core []Tool
	cands := map[string]Tool{}
	var candList []candidate
	eligible := 0
	for _, t := range c.tools {
		if !phaseEligible(t.Phases, q.Phase, q.PhaseOrder) {
			continue
		}
		eligible++
		if t.AlwaysOn {
			core = append(core, t)
			continue
		}
		cands[t.Name] = t
		candList = append(candList, candidate{t.Name, firstLine(t.Description)})
	}

	k := max - len(core)
	if k < 0 {
		k = 0
	}

	if gen == nil || k == 0 || len(candList) == 0 {
		return c.Select(q), true
	}

	// Order candidates by BM25 so the prompt presents the strongest lexical hints first (helps the
	// model without constraining it — it still sees every candidate).
	qToks := tokenize(q.Task)
	sort.SliceStable(candList, func(i, j int) bool {
		si, sj := c.score(qToks, candList[i].Name), c.score(qToks, candList[j].Name)
		if si != sj {
			return si > sj
		}
		return candList[i].Name < candList[j].Name
	})

	out, err := gen.Generate(ctx, buildRankPrompt(q.Task, candList, k))
	if err != nil {
		return c.Select(q), true
	}
	picks := parseToolList(out)
	if len(picks) == 0 {
		return c.Select(q), true
	}

	// DISPOSE: closed-set + cap + dedupe, core first.
	sel = Selection{Scores: map[string]float64{}}
	for _, t := range core {
		sel.Tools = append(sel.Tools, t)
	}
	added := map[string]bool{}
	for _, name := range picks {
		if len(sel.Tools) >= max {
			break
		}
		t, ok := cands[name] // closed-set: must be a real eligible candidate
		if !ok || added[name] {
			continue
		}
		added[name] = true
		sel.Tools = append(sel.Tools, t)
	}
	sel.Withheld = eligible - len(sel.Tools)
	if sel.Withheld < 0 {
		sel.Withheld = 0
	}
	return sel, false
}

// buildRankPrompt asks the model to choose the ≤k most relevant tools for the task, returning ONLY a
// JSON array of tool names — parseable and closed-set-checkable.
func buildRankPrompt(task string, cands []candidate, k int) string {
	var b strings.Builder
	fmt.Fprintf(&b, "You are selecting the tools an autonomous security agent should have active for ONE subgoal.\n")
	fmt.Fprintf(&b, "Pick the %d MOST RELEVANT tools for the task — fewer is better; omit anything not needed.\n\n", k)
	fmt.Fprintf(&b, "TASK: %s\n\nAVAILABLE TOOLS:\n", task)
	for _, c := range cands {
		fmt.Fprintf(&b, "- %s: %s\n", c.Name, c.Description)
	}
	fmt.Fprintf(&b, "\nReturn ONLY a JSON array of the chosen tool names, most relevant first, e.g. [\"a\",\"b\"]. No prose.")
	return b.String()
}

// parseToolList extracts the tool-name array from a model response, tolerating prose/markdown fences
// around the JSON array. Returns nil if no array is found.
func parseToolList(s string) []string {
	i := strings.IndexByte(s, '[')
	j := strings.LastIndexByte(s, ']')
	if i < 0 || j <= i {
		return nil
	}
	var arr []string
	if err := json.Unmarshal([]byte(s[i:j+1]), &arr); err != nil {
		return nil
	}
	out := make([]string, 0, len(arr))
	for _, v := range arr {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	return out
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if len(s) > 200 {
		s = s[:200]
	}
	return strings.TrimSpace(s)
}
