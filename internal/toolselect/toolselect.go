// Package toolselect is a reusable, best-in-class dynamic tool-selection layer for the L2 agents.
//
// The problem it solves (CLAUDE.md §2.6, "L2-CAP"): an agent may have a large capability library, but
// LLM tool-use accuracy degrades steeply past ~12 tools in the prompt. The winning pattern is "many
// tools available, a small subset ACTIVE at a time, chosen by the task at hand." tsengine already has
// two of the three standard techniques wired in internal/l2:
//
//  1. Phase-scoped catalog   — expose only the tools relevant to the current OODA phase (phase.go).
//  2. Dispatch gateway        — one slot (dispatch_l2_probe / dispatch_oss) fronts a whole tool family.
//
// The missing third technique is TASK-BASED RETRIEVAL: given the agent's current subgoal, rank the
// library and surface only the top-k relevant tools (plus always-on core tools), capped at MaxActive.
// This package is that retriever — deterministic, offline, dependency-free (a lightweight BM25-style
// lexical scorer over each tool's name/tags/description), with an optional LLM refiner (llm.go) that
// PROPOSES a final subset the deterministic layer DISPOSES (closed-set, cap-enforced) — the same
// "model proposes, framework disposes" grounding discipline as the rest of the engine (§10).
//
// It is a library: the agents (webagent / cloudagent / l2 Lead) adopt it to shape the prompt's tool
// section each turn. It never executes a tool and never invents one — it only ranks + filters the
// caller's real, registered catalog.
package toolselect

import (
	"math"
	"sort"
)

// Tool is one entry in an agent's capability library. Description is the full help text the agent
// would otherwise put in the prompt; it doubles as the searchable corpus.
type Tool struct {
	Name        string
	Description string
	Tags        []string // curated relevance hints (e.g. {"sqli","injection","blind"}); weighted above prose
	Phases      []string // allowed phases (empty = all phases); a tool is eligible in its phase or any later one
	AlwaysOn    bool     // CORE tool — always active regardless of relevance (e.g. send_request, record_finding, finish)
}

// Query is a selection request: the current subgoal text + optional phase + the active-set cap.
type Query struct {
	Task       string   // the agent's current subgoal / intent (the retrieval query)
	Phase      string   // current phase; "" disables phase filtering
	PhaseOrder []string // the forward phase progression (for "eligible in this phase or later"); nil disables ordering (exact-match only)
	MaxActive  int      // hard cap on the active set (default DefaultMaxActive)
}

// Selection is the result: the active subset (always-on first, then by descending relevance), the raw
// scores (observability), and how many eligible tools were withheld.
type Selection struct {
	Tools    []Tool
	Scores   map[string]float64
	Withheld int
}

// DefaultMaxActive mirrors the L2-CAP (§2.6): keep the LLM-visible tool set at or under 12.
const DefaultMaxActive = 12

// Catalog is a precomputed, reusable index over a tool library.
type Catalog struct {
	tools []Tool
	docs  map[string][]string // tool name → tokenized searchable text
	idf   map[string]float64  // token → inverse document frequency
	avgDL float64
}

// NewCatalog builds the index once; Select is then cheap to call per turn.
func NewCatalog(tools []Tool) *Catalog {
	c := &Catalog{tools: tools, docs: make(map[string][]string, len(tools)), idf: map[string]float64{}}
	df := map[string]int{}
	total := 0
	for _, t := range tools {
		toks := c.tokensFor(t)
		c.docs[t.Name] = toks
		total += len(toks)
		seen := map[string]bool{}
		for _, tok := range toks {
			if !seen[tok] {
				df[tok]++
				seen[tok] = true
			}
		}
	}
	n := float64(len(tools))
	for tok, d := range df {
		// BM25 idf (smoothed, always positive).
		c.idf[tok] = math.Log(1 + (n-float64(d)+0.5)/(float64(d)+0.5))
	}
	if len(tools) > 0 {
		c.avgDL = float64(total) / n
	}
	return c
}

// tokensFor builds a tool's searchable token stream, repeating name + tag tokens so an exact tag/name
// hit outweighs an incidental prose mention (the curated relevance signal dominates).
func (c *Catalog) tokensFor(t Tool) []string {
	var toks []string
	nameToks := tokenize(t.Name)
	for i := 0; i < 3; i++ { // name weight ×3
		toks = append(toks, nameToks...)
	}
	for _, tag := range t.Tags {
		tt := tokenize(tag)
		for i := 0; i < 3; i++ { // tag weight ×3
			toks = append(toks, tt...)
		}
	}
	toks = append(toks, tokenize(t.Description)...)
	return toks
}

// Select ranks the eligible tools against the task and returns the capped active subset. Always-on
// tools are always included (and don't compete for a relevance slot); the remaining slots go to the
// highest-scoring eligible tools. A tool with zero relevance is never surfaced unless always-on — so
// an off-task specialist stays hidden (the whole point).
func (c *Catalog) Select(q Query) Selection {
	max := q.MaxActive
	if max <= 0 {
		max = DefaultMaxActive
	}
	qToks := tokenize(q.Task)

	type scored struct {
		t     Tool
		score float64
	}
	var core []Tool
	var cand []scored
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
		cand = append(cand, scored{t, c.score(qToks, t.Name)})
	}

	// Stable, deterministic ordering: score desc, then name asc for ties.
	sort.SliceStable(cand, func(i, j int) bool {
		if cand[i].score != cand[j].score {
			return cand[i].score > cand[j].score
		}
		return cand[i].t.Name < cand[j].t.Name
	})

	sel := Selection{Scores: map[string]float64{}}
	for _, t := range core {
		sel.Tools = append(sel.Tools, t)
		sel.Scores[t.Name] = math.Inf(1) // always-on
	}
	slots := max - len(core)
	picked := 0
	for _, s := range cand {
		if picked >= slots || s.score <= 0 {
			break // cap reached, or no remaining tool is relevant to the task
		}
		sel.Tools = append(sel.Tools, s.t)
		sel.Scores[s.t.Name] = s.score
		picked++
	}
	sel.Withheld = eligible - len(sel.Tools)
	if sel.Withheld < 0 {
		sel.Withheld = 0
	}
	return sel
}

// score is BM25 of the task query against one tool's document.
func (c *Catalog) score(qToks []string, name string) float64 {
	const k1, b = 1.5, 0.75
	doc := c.docs[name]
	if len(doc) == 0 {
		return 0
	}
	tf := map[string]int{}
	for _, tok := range doc {
		tf[tok]++
	}
	dl := float64(len(doc))
	var s float64
	for _, qt := range dedupeStrings(qToks) {
		f := float64(tf[qt])
		if f == 0 {
			continue
		}
		idf := c.idf[qt]
		if idf == 0 {
			continue
		}
		s += idf * (f * (k1 + 1)) / (f + k1*(1-b+b*dl/c.avgDL))
	}
	return s
}

// Names is a convenience: the selected tool names in order.
func (s Selection) Names() []string {
	out := make([]string, len(s.Tools))
	for i, t := range s.Tools {
		out[i] = t.Name
	}
	return out
}

// phaseEligible reports whether a tool is usable in the current phase. Empty tool-phases = all phases.
// With a PhaseOrder, a tool allowed in phase X is also allowed in every LATER phase (later phases keep
// earlier capabilities — the l2 "allowedInPhase" semantics). Without PhaseOrder, it's exact-match.
func phaseEligible(toolPhases []string, current string, order []string) bool {
	if current == "" || len(toolPhases) == 0 {
		return true
	}
	if len(order) == 0 {
		for _, p := range toolPhases {
			if p == current {
				return true
			}
		}
		return false
	}
	ci := indexOf(order, current)
	if ci < 0 {
		return true // unknown current phase → don't over-filter
	}
	for _, p := range toolPhases {
		if pi := indexOf(order, p); pi >= 0 && ci >= pi {
			return true
		}
	}
	return false
}

func indexOf(ss []string, s string) int {
	for i, v := range ss {
		if v == s {
			return i
		}
	}
	return -1
}

func dedupeStrings(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
