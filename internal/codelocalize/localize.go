// Package codelocalize is the vulnerability-LOCALIZATION substrate for the AI Security Engineer —
// the "given a vulnerability class, WHERE in this repo is the sink?" capability (the G1 code-depth gap).
//
// Design lineage: Cisco's Antares (open-weight vuln-localization SLMs). Antares' insight is that
// localization is a distinct job from detection or patching: a scanner (or an advisory) tells you a
// CWE class exists; the expensive human work is navigating an unfamiliar repo to the actual sink and
// pruning the false-positive triage that rule-heavy static analysis leaves behind. codelocalize does
// exactly that job and nothing else — it takes a vulnerability description (CWE + text) plus a source
// tree and returns a RANKED list of candidate files, each with the concrete evidence (file:line) that
// put it there, plus an exploration trace.
//
// Two tiers, mirroring the ADR-0008 "agent proposes, framework disposes" model (llmspec.go):
//
//   - HeuristicLocalizer (this file + heuristic.go): fully deterministic, LLM-free. A per-CWE
//     source→sink signal table scored by evidence density. This is the substrate baseline and the
//     honest floor — it needs no key, is trivially testable, and grounds every rank in a real matched
//     token at a real line (§10). It is also the benchmark's ablation baseline (substrate-vs-agent).
//
//   - LLMLocalizer (llm.go): wraps the model seam to PROPOSE a ranking for classes/idioms the token
//     table can't see, but every proposed path is DISPOSED by the deterministic grounder — it must
//     exist in the repo AND carry a plausible sink token — so the model can widen recall but can NEVER
//     invent a file (no LLM false positives, §10). Falls back to the heuristic when the model is absent
//     or proposes nothing groundable.
//
// codelocalize adds NO detection (§13): it re-points evidence the tree already has at the "where"
// question. It is host-side, pure Go, needs no sandbox rebuild.
package codelocalize

import (
	"context"
	"sort"
	"strings"

	"github.com/ClatTribe/tsengine/pkg/types"
)

// Query is a localization request: the vulnerability class to locate. It is intentionally decoupled
// from types.Finding so a localizer can be driven by an advisory / CWE alone (Antares' "start from a
// vulnerability description") as well as by an emitted scanner finding.
type Query struct {
	CWE         []string // e.g. ["CWE-89"] — the primary localization key
	Title       string   // short vuln title (keyword source)
	Description string   // free-text advisory / finding description (keyword source)
}

// QueryFromFinding builds a localization Query from an emitted finding.
func QueryFromFinding(f types.Finding) Query {
	return Query{CWE: f.CWE, Title: f.Title, Description: f.Description}
}

// keywords returns the lowercased, de-noised free-text tokens (title+description) used as a weak
// corroborating signal on top of the CWE sink table. Short/stopword tokens are dropped so a common
// English word can't dominate the score.
func (q Query) keywords() []string {
	seen := map[string]bool{}
	var out []string
	for _, tok := range strings.FieldsFunc(strings.ToLower(q.Title+" "+q.Description), func(r rune) bool {
		return !(r >= 'a' && r <= 'z') && !(r >= '0' && r <= '9')
	}) {
		if len(tok) < 4 || stopwords[tok] || seen[tok] {
			continue
		}
		seen[tok] = true
		out = append(out, tok)
	}
	return out
}

var stopwords = map[string]bool{
	"this": true, "that": true, "with": true, "from": true, "into": true, "when": true, "will": true,
	"vulnerability": true, "vulnerable": true, "found": true, "issue": true, "attacker": true,
	"could": true, "which": true, "these": true, "their": true, "there": true, "http": true,
	"https": true, "request": true, "response": true, "allows": true, "using": true, "value": true,
}

// Candidate is one ranked source file, with the evidence that ranked it.
type Candidate struct {
	Path       string   `json:"path"`
	Score      float64  `json:"score"`
	Confidence float64  `json:"confidence"` // 0–1, derived from evidence KIND (strong sink + source > weak-only); capped <1 (a heuristic is never certain — §10). Lets a consumer threshold.
	Reasons    []string `json:"reasons"`    // human-readable "file:line matched <token> (sink|source|keyword)"
}

// Result is a ranked localization: the most-likely-sink files first, plus the exploration trace.
type Result struct {
	Ranked []Candidate `json:"ranked"`
	Trace  []string    `json:"trace"`  // the investigator's steps (what was searched, why it ranked)
	Engine string      `json:"engine"` // "heuristic" | "llm+heuristic"
}

// TopPaths returns the top-n candidate paths (convenience for callers/benches).
func (r Result) TopPaths(n int) []string {
	var out []string
	for i, c := range r.Ranked {
		if i >= n {
			break
		}
		out = append(out, c.Path)
	}
	return out
}

// Localizer is the localization interface both tiers satisfy.
type Localizer interface {
	// Localize ranks the repo's files by likelihood of containing the queried vulnerability's sink.
	Localize(ctx context.Context, q Query, repo Repo) (Result, error)
}

// rankCandidates sorts scored candidates deterministically: score desc, then path asc (so a tie never
// depends on map iteration order — §10 reproducibility for the bench and the evidence pack).
func rankCandidates(cs []Candidate) {
	sort.SliceStable(cs, func(i, j int) bool {
		if cs[i].Score != cs[j].Score {
			return cs[i].Score > cs[j].Score
		}
		return cs[i].Path < cs[j].Path
	})
}
