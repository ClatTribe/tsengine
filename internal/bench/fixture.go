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
	"strings"

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

	// MaxSeverity is the false-positive severity FLOOR for a benign /
	// FP-control fixture: any raw finding AT OR ABOVE this severity on a
	// target that should be clean is counted as a false positive. This is
	// the robust FP-rate gate — unlike MaxFindings (a total-count cap), it
	// tolerates harmless info-level notes a clean target legitimately emits
	// while still failing on any actionable (high/critical) false alarm.
	// Empty = no severity gate. Typical: "high".
	MaxSeverity types.Severity `json:"max_severity,omitempty"`

	// PassRecall is the minimum detection recall to pass (default 1.0).
	PassRecall float64 `json:"pass_recall,omitempty"`

	// Competitors is MANDATORY — every fixture cites its neutral
	// leaderboard so reports are always comparable (CLAUDE.md §14.2).
	Competitors Competitors `json:"competitors"`

	// Runnable=false marks a stub fixture whose corpus must be deployed
	// out-of-band (WAVSEP webapp, OWASP BenchmarkJava tree). The harness
	// skips running it but still renders its competitor numbers.
	Runnable bool `json:"runnable"`

	// DocumentedVulnerabilities is the target's OWN documented defect list — the
	// HONEST DENOMINATOR. MustFind carries only the subset a scan can currently
	// surface, so that a fixture is a measurement rather than a permanently-red
	// gate; this records everything the target actually contains so the gap is
	// not quietly defined away.
	//
	// IT MUST BE READ, NOT MERELY WRITTEN. These fields were present in
	// fixtures/api/vampi/fixture.json with a note explaining they exist "so the
	// gap stays visible instead of being quietly defined away" — and the struct
	// had no field for either, so json.Unmarshal dropped both and no report ever
	// mentioned them. The denominator was visible only to someone who opened the
	// JSON, which is the same failure the note warns about, one level up.
	//
	// The consequence is specific: a fixture whose MustFind holds one token scores
	// `detection_recall: 1.000` and reads as "we find everything", when the honest
	// statement is "we find 1 of the 9 defects this target deliberately contains".
	DocumentedVulnerabilities []DocumentedVuln `json:"documented_vulnerabilities,omitempty"`
	// GroundTruthNote explains why MustFind is narrower than the documented list.
	GroundTruthNote string `json:"ground_truth_note,omitempty"`
}

// DocumentedVuln is one defect the target is documented to contain, whether or not
// anything here can currently detect it.
type DocumentedVuln struct {
	Class    string `json:"class"`
	Endpoint string `json:"endpoint,omitempty"`
	CWE      string `json:"cwe,omitempty"`
	// CoveredBy names the tool or component that detects it, or says plainly that
	// nothing does. "NOT COVERED" (case-insensitive prefix) is what Covered reads.
	CoveredBy string `json:"covered_by,omitempty"`
	// OWASPAPI is the OWASP API Security Top 10 (2023) item this maps to — "API1"
	// … "API10". Empty when the class is not on that list at all, which is itself
	// worth recording: VAmPI's headline SQL injection is not a 2023 Top 10 item,
	// because Injection was folded away when the list was revised.
	OWASPAPI string `json:"owasp_api,omitempty"`
}

// Covered reports whether anything in the product detects this class today. It reads
// CoveredBy rather than taking a separate boolean, so the prose and the flag cannot
// disagree — the failure mode where a field says "NOT COVERED" beside covered:true.
func (d DocumentedVuln) Covered() bool {
	return !strings.HasPrefix(strings.ToUpper(strings.TrimSpace(d.CoveredBy)), "NOT COVERED")
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
	if f.MaxSeverity != "" && !f.MaxSeverity.Valid() {
		return fmt.Errorf("invalid max_severity %q", f.MaxSeverity)
	}
	return nil
}
