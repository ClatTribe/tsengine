// Package bench is the L1 benchmark harness. It runs the real tsengine
// binary against a fixture, scores the output against expected results,
// and renders a report that always cites the neutral competitor
// leaderboard (CLAUDE.md §14).
//
// Scoring is SUT-agnostic: the scorer reads expectations from fixture
// DATA and never hardcodes a target identifier. The anti-overfit guard
// (guard_test.go) enforces this by source-grepping the scoring files.
package bench

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/ClatTribe/tsengine/pkg/types"
)

// Metric names a fixture's scoring mode.
const (
	MetricMustFindRecall = "must_find_recall" // recall on must_find[]
	MetricFPRate         = "fp_rate"          // benign target: assert few/no findings
	MetricYouden         = "youden"           // sensitivity + specificity - 1
)

// Fixture is a single benchmark case loaded from fixture.json.
type Fixture struct {
	Name        string `json:"name"`
	Asset       string `json:"asset"`
	Target      string `json:"target"`
	Description string `json:"description"`
	Metric      string `json:"metric"`

	// MustFind: rule_id / CVE substrings that SHOULD appear (true
	// positives). MustNotFind: substrings that must NOT appear (false
	// positives). MaxFindings: for benign fixtures, an upper bound on
	// total findings.
	MustFind    []string `json:"must_find,omitempty"`
	MustNotFind []string `json:"must_not_find,omitempty"`
	// MaxFindings is an inclusive upper bound on total raw findings for
	// benign fixtures. nil = no limit; a set value (including 0) is
	// enforced. Pointer so "at most 0 findings" is expressible.
	MaxFindings *int `json:"max_findings,omitempty"`

	// PassRecall is the minimum detection recall to pass (default 1.0).
	PassRecall float64 `json:"pass_recall,omitempty"`

	// Competitors is MANDATORY — every fixture cites its neutral
	// leaderboard so reports are always comparable (CLAUDE.md §14.2).
	Competitors Competitors `json:"competitors"`

	// Runnable=false marks a stub fixture whose corpus must be deployed
	// out-of-band (WAVSEP webapp, OWASP BenchmarkJava tree). The harness
	// skips running it but still renders its competitor numbers.
	Runnable bool `json:"runnable"`
}

// Competitors carries the neutral competitor scorecard for a fixture.
type Competitors struct {
	Leaderboard string            `json:"leaderboard"`
	Scores      map[string]string `json:"scores,omitempty"`
	Note        string            `json:"note,omitempty"`
}

// Load reads a fixture.json from a fixture directory or file path.
func Load(path string) (*Fixture, error) {
	if fi, err := os.Stat(path); err == nil && fi.IsDir() {
		path = path + "/fixture.json"
	}
	data, err := os.ReadFile(path) //nolint:gosec // operator-provided fixture path
	if err != nil {
		return nil, fmt.Errorf("bench: read fixture %s: %w", path, err)
	}
	var f Fixture
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("bench: parse fixture %s: %w", path, err)
	}
	if err := f.validate(); err != nil {
		return nil, fmt.Errorf("bench: fixture %s: %w", path, err)
	}
	return &f, nil
}

func (f *Fixture) validate() error {
	if f.Name == "" {
		return fmt.Errorf("missing name")
	}
	if !types.AssetType(f.Asset).Valid() {
		return fmt.Errorf("invalid asset %q", f.Asset)
	}
	// Mandatory competitor citation — the load-bearing anti-overfit
	// guard (CLAUDE.md §14.2.2). A fixture with no competitor context is
	// not a valid benchmark.
	if f.Competitors.Leaderboard == "" && f.Competitors.Note == "" {
		return fmt.Errorf("fixture must cite competitors (leaderboard or note)")
	}
	if f.PassRecall == 0 {
		f.PassRecall = 1.0
	}
	return nil
}
