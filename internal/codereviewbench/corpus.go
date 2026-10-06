// Package codereviewbench is a HELD-OUT benchmark for AI source review — the DeepSecBench recipe,
// rebuilt on public data so anyone can check our answer key.
//
// WHY IT EXISTS. Vercel's DeepSecBench is the only public number for "how much does an AI reviewer find
// in real code", and its corpus is deliberately secret (repository, commit, files and findings are not
// disclosed), so nobody else can score against it. Without a corpus of our own, the claim "codesweep
// finds vulnerabilities" or "deepsec is better than codesweep" is a sentence, not a measurement.
//
// THE RECIPE. Each case is one published GitHub security advisory with exactly one fix commit. The
// repository is pinned at that commit's PARENT — the code as it was the moment before the fix — and the
// answer key is the set of source lines the fix changed. A reviewer pointed at the pre-fix tree either
// reports something at those lines or it does not.
//
// WHAT THE ANSWER KEY IS AND IS NOT, stated because a benchmark that overstates its key overstates every
// number computed from it:
//   - The fix's changed lines APPROXIMATE the vulnerable location. A fix that adds a check in the caller
//     marks the caller, not the sink. So recall is reported two ways: strict (a prediction within a few
//     lines of a changed line) and lenient (a prediction anywhere in a changed file).
//   - Predictions beyond the key are UNJUDGED, not false. An advisory names one bug; the same code may hold
//     others nobody has reported. So precision is a LOWER BOUND (unjudged counted as wrong) and is labelled
//     as one, never presented as the precision.
//   - Advisories are chosen recent and the publication date is recorded per case, because a case published
//     before a model's training cutoff may be one it has memorised. The report says how many cases fall
//     after a given cutoff rather than pretending the question does not arise.
//
// HELD-OUT DISCIPLINE (§14.2 rule 5): once this corpus has been used to tune a reviewer it is no longer
// held out. The package test refuses SUT-specific identifiers (case repositories) in the reviewers'
// source, and record the first number BEFORE closing any gap it names.
package codereviewbench

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Range is a span of lines in one file of the PRE-FIX tree, inclusive.
type Range struct {
	File  string `json:"file"`
	Start int    `json:"start"`
	End   int    `json:"end"`
}

// Case is one advisory pinned at the commit before its fix.
type Case struct {
	ID           string   `json:"id"` // GHSA id
	Ecosystem    string   `json:"ecosystem"`
	Repo         string   `json:"repo"` // owner/name on github.com
	PreFixCommit string   `json:"pre_fix_commit"`
	FixCommit    string   `json:"fix_commit"`
	PublishedAt  string   `json:"published_at"` // YYYY-MM-DD
	Severity     string   `json:"severity"`
	CWEs         []string `json:"cwes"`
	Summary      string   `json:"summary"`
	Source       string   `json:"source"` // the advisory URL — so the key is checkable, not taken on our word
	Golden       []Range  `json:"golden"`
}

// Validate refuses a case that cannot be scored honestly.
func (c Case) Validate() error {
	switch {
	case c.ID == "" || c.Repo == "" || c.Source == "":
		return fmt.Errorf("case %q: id, repo and source are required", c.ID)
	case len(c.PreFixCommit) < 7 || len(c.FixCommit) < 7:
		return fmt.Errorf("case %s: both commits are required", c.ID)
	case len(c.Golden) == 0:
		return fmt.Errorf("case %s: no answer key — a case with nothing to find measures nothing", c.ID)
	}
	for _, g := range c.Golden {
		if g.File == "" || g.Start <= 0 || g.End < g.Start {
			return fmt.Errorf("case %s: bad range %+v", c.ID, g)
		}
	}
	return nil
}

// Files returns the distinct files the answer key names.
func (c Case) Files() []string {
	seen := map[string]bool{}
	var out []string
	for _, g := range c.Golden {
		if !seen[g.File] {
			seen[g.File] = true
			out = append(out, g.File)
		}
	}
	sort.Strings(out)
	return out
}

// Load reads every *.json case in dir, sorted by id. A malformed or invalid case is an ERROR, never
// skipped: a corpus that quietly drops cases scores a smaller, easier benchmark under the same name.
func Load(dir string) ([]Case, error) {
	paths, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil {
		return nil, err
	}
	if len(paths) == 0 {
		return nil, fmt.Errorf("no cases in %s", dir)
	}
	out := make([]Case, 0, len(paths))
	seen := map[string]bool{}
	for _, p := range paths {
		raw, err := os.ReadFile(p) //nolint:gosec // benchmark corpus path supplied by the operator
		if err != nil {
			return nil, err
		}
		var c Case
		if err := json.Unmarshal(raw, &c); err != nil {
			return nil, fmt.Errorf("%s: %w", filepath.Base(p), err)
		}
		if err := c.Validate(); err != nil {
			return nil, err
		}
		if seen[c.ID] {
			return nil, fmt.Errorf("duplicate case %s", c.ID)
		}
		seen[c.ID] = true
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// normPath makes a reviewer's path comparable with the key: forward slashes, no leading "./" or "/",
// and a workspace prefix (a sandbox mount, a clone dir) stripped when the reviewer reported an absolute
// path that ends in the key's relative one.
func normPath(p string) string {
	p = strings.ReplaceAll(strings.TrimSpace(p), "\\", "/")
	p = strings.TrimPrefix(p, "./")
	return strings.TrimPrefix(p, "/")
}

func samePath(pred, key string) bool {
	pred, key = normPath(pred), normPath(key)
	return pred == key || strings.HasSuffix(pred, "/"+key)
}
