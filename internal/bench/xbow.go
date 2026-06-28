package bench

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/ClatTribe/tsengine/pkg/types"
)

// xbow.go adapts the XBOW validation-benchmarks suite (github.com/xbow-engineering/
// validation-benchmarks): 104 confidential-until-release web challenges XBOW's own security team
// uses, each a Dockerized vulnerable app whose success criterion is FLAG CAPTURE. A random flag is
// injected at build time (`docker compose build --build-arg flag=<flag>`) and hidden in the app;
// "solving" the benchmark = retrieving that flag by exploiting the vuln.
//
// That criterion is why this is the right rung-2 yardstick (see docs): it is XBOW's OWN public
// suite, so our number is directly comparable; and flag capture is deterministic + ungameable — a
// high-entropy secret the agent can only possess by genuinely exploiting the app. So it doubles as
// a perfect fit for our grounding model (§10): a benchmark "win" is itself evidence-grounded
// (the agent captured the real flag), never self-graded by an LLM.
//
// This file is the PURE, unit-tested core — parse the suite, grade flag capture, aggregate the
// scoreboard. The live build → up → scan → grade → down orchestration lives in cmd/tsbench (Docker
// + sandbox-image + LLM gated). Keeping the metric logic here and offline-tested means it is
// correct BEFORE the first heavy live run.

// XBOWConfig is the per-benchmark metadata file (benchmark/benchmark-config.json).
type XBOWConfig struct {
	Name         string   `json:"name"`
	Description  string   `json:"description"`
	Level        int      `json:"level"`         // 1=easy, 2=medium, 3=hard
	WinCondition string   `json:"win_condition"` // "flag" | "question"
	Tags         []string `json:"tags"`
}

// XBOWBenchmark is one loaded challenge: its parsed config + the directory holding its
// docker-compose.yml (the unit cmd/tsbench builds and runs).
type XBOWBenchmark struct {
	ID     string     `json:"id"`  // the benchmark directory name (e.g. "XBEN-001-24")
	Dir    string     `json:"dir"` // path to the benchmark dir (where docker-compose.yml lives)
	Config XBOWConfig `json:"config"`
}

// ComposeFile returns the benchmark's docker-compose file path if one exists, else "".
func (b XBOWBenchmark) ComposeFile() string {
	for _, name := range []string{"docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"} {
		p := filepath.Join(b.Dir, name)
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
			return p
		}
	}
	return ""
}

// LoadXBOWSuite walks a cloned validation-benchmarks tree and returns every benchmark whose
// benchmark/benchmark-config.json parses. Accepts the repo root, its benchmarks/ subdir, or any
// ancestor — it simply finds every benchmark-config.json beneath `root`. The benchmark dir (and ID)
// is the directory CONTAINING the benchmark/ folder, so docker-compose.yml resolves alongside it.
func LoadXBOWSuite(root string) ([]XBOWBenchmark, error) {
	if fi, err := os.Stat(root); err != nil || !fi.IsDir() {
		return nil, fmt.Errorf("xbow suite: %s is not a directory", root)
	}
	var out []XBOWBenchmark
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil // skip unreadable subtrees rather than abort the whole load
		}
		if d.IsDir() || d.Name() != "benchmark-config.json" {
			return nil
		}
		data, rerr := os.ReadFile(path) //nolint:gosec // operator-provided suite path
		if rerr != nil {
			return nil
		}
		var cfg XBOWConfig
		if jerr := json.Unmarshal(data, &cfg); jerr != nil {
			return nil // a malformed config is skipped, not fatal — load the rest of the suite
		}
		// path = <root>/<ID>/benchmark/benchmark-config.json → benchmark dir = parent-of-parent.
		benchDir := filepath.Dir(filepath.Dir(path))
		out = append(out, XBOWBenchmark{ID: filepath.Base(benchDir), Dir: benchDir, Config: cfg})
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("xbow suite: walk %s: %w", root, err)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("xbow suite: no benchmark-config.json found under %s (clone github.com/xbow-engineering/validation-benchmarks)", root)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// GenerateFlag returns a high-entropy flag to inject at a benchmark's build time. The randomness is
// exactly what makes capture ungameable: the agent cannot guess or fabricate it — it can only
// reproduce the string by reading it out of the app it actually exploited.
func GenerateFlag() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("xbow: generate flag: %w", err)
	}
	return "flag{" + hex.EncodeToString(b[:]) + "}", nil
}

// FlagCaptured reports whether the injected flag appears anywhere in the agent's captured evidence —
// the deterministic, ungameable success criterion. An empty flag or empty evidence is never a win
// (a guard against a blank flag matching the empty string and falsely "solving" everything).
func FlagCaptured(flag, evidence string) bool {
	flag = strings.TrimSpace(flag)
	return flag != "" && evidence != "" && strings.Contains(evidence, flag)
}

// FlagCapturedInScan marshals a completed scan and checks every captured field (titles,
// descriptions, raw tool output, evidence bundles — wherever an exploited response landed) for the
// flag. This is how the live runner grades: the whole scan artifact is the agent's evidence.
func FlagCapturedInScan(flag string, scan *types.Scan) bool {
	if scan == nil {
		return false
	}
	data, err := json.Marshal(scan)
	if err != nil {
		return false
	}
	return FlagCaptured(flag, string(data))
}

// XBOWResult is the outcome for one benchmark run.
type XBOWResult struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Level    int      `json:"level"`
	Tags     []string `json:"tags,omitempty"`
	Solved   bool     `json:"solved"`
	Duration float64  `json:"duration_sec,omitempty"`
	Note     string   `json:"note,omitempty"` // "flag captured" or a build/run/grade error
}

// LevelAgg is a solved/total tally for one difficulty level or tag.
type LevelAgg struct {
	Total  int `json:"total"`
	Solved int `json:"solved"`
}

// Rate is the solved fraction (0 when no benchmarks in the bucket).
func (a LevelAgg) Rate() float64 {
	if a.Total == 0 {
		return 0
	}
	return float64(a.Solved) / float64(a.Total)
}

// XBOWScoreboard aggregates results into the shape XBOW reports: an overall solve-rate plus the
// per-difficulty-level breakdown (and a per-tag cut showing which vuln classes we're strong/weak on).
type XBOWScoreboard struct {
	Total     int                 `json:"total"`
	Solved    int                 `json:"solved"`
	SolveRate float64             `json:"solve_rate"`
	ByLevel   map[int]LevelAgg    `json:"by_level"`
	ByTag     map[string]LevelAgg `json:"by_tag,omitempty"`
}

// AggregateXBOW rolls per-benchmark results into the scoreboard (overall + per-level + per-tag).
func AggregateXBOW(results []XBOWResult) XBOWScoreboard {
	sb := XBOWScoreboard{ByLevel: map[int]LevelAgg{}, ByTag: map[string]LevelAgg{}}
	for _, r := range results {
		sb.Total++
		lvl := sb.ByLevel[r.Level]
		lvl.Total++
		for _, t := range r.Tags {
			t = strings.ToLower(strings.TrimSpace(t))
			if t == "" {
				continue
			}
			ta := sb.ByTag[t]
			ta.Total++
			if r.Solved {
				ta.Solved++
			}
			sb.ByTag[t] = ta
		}
		if r.Solved {
			sb.Solved++
			lvl.Solved++
		}
		sb.ByLevel[r.Level] = lvl
	}
	if sb.Total > 0 {
		sb.SolveRate = float64(sb.Solved) / float64(sb.Total)
	}
	return sb
}

// RenderXBOWScoreboard renders the markdown scoreboard. It ALWAYS cites the XBOW suite as the
// competitor yardstick (anti-overfit §14.2): this is XBOW's own public benchmark, so the number is
// directly comparable to XBOW's published solve-rate on the same 104 challenges.
func RenderXBOWScoreboard(sb XBOWScoreboard) string {
	var b strings.Builder
	b.WriteString("=== XBOW validation-benchmarks — flag-capture scoreboard ===\n")
	b.WriteString("Suite: github.com/xbow-engineering/validation-benchmarks (104 web challenges, flag-capture)\n")
	b.WriteString("Competitor yardstick: XBOW (suite authors) publish their own solve-rate on THIS suite — same-suite, directly comparable.\n")
	b.WriteString("Success = the build-time-injected random flag was captured in the agent's evidence (deterministic, ungameable, §10-grounded).\n\n")
	fmt.Fprintf(&b, "OVERALL: %d/%d solved = %.1f%%\n", sb.Solved, sb.Total, 100*sb.SolveRate)

	if len(sb.ByLevel) > 0 {
		b.WriteString("\nby difficulty:\n")
		levels := make([]int, 0, len(sb.ByLevel))
		for l := range sb.ByLevel {
			levels = append(levels, l)
		}
		sort.Ints(levels)
		for _, l := range levels {
			a := sb.ByLevel[l]
			fmt.Fprintf(&b, "  level %d (%s): %d/%d = %.1f%%\n", l, levelName(l), a.Solved, a.Total, 100*a.Rate())
		}
	}

	if len(sb.ByTag) > 0 {
		b.WriteString("\nby vuln class:\n")
		tags := make([]string, 0, len(sb.ByTag))
		for t := range sb.ByTag {
			tags = append(tags, t)
		}
		sort.Strings(tags)
		for _, t := range tags {
			a := sb.ByTag[t]
			fmt.Fprintf(&b, "  %-18s %d/%d = %.1f%%\n", t, a.Solved, a.Total, 100*a.Rate())
		}
	}
	return b.String()
}

func levelName(l int) string {
	switch l {
	case 1:
		return "easy"
	case 2:
		return "medium"
	case 3:
		return "hard"
	default:
		return "?"
	}
}
