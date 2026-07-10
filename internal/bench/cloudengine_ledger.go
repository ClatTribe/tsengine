package bench

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// cloudengine_ledger.go — the durable, append-only record of the AI Cloud Engineer HEAD-TO-HEAD (the L2
// agent vs the bounded substrate). The xbow + defense benchmarks have ledgers so progress is a real
// artifact, not a slogan; the cloud-engine L2 evaluation (discrimination → lift → scorecard → ranking →
// remediation) had none — each run's grade evaporated, so a tuning campaign couldn't answer "is the agent
// getting BETTER?". This closes that: one appended JSON line per --agent run (git-committed + diffable),
// keyed by the account seed, carrying the graded L2 score + lift + verified remediation. The summary rolls
// it into the trend an operator tunes against — over the DISCRIMINATING runs only (a non-discriminating run
// didn't evaluate the agent, so it can't count toward the agent's score, §14 anti-overfit).

// CloudEngineLedgerEntry is one durable record of a single head-to-head run on a seeded account.
type CloudEngineLedgerEntry struct {
	TS             string  `json:"ts"` // RFC3339 UTC — lexicographic order == chronological (stamped by the caller)
	Seed           int64   `json:"seed"`
	ScaleBudget    int     `json:"scale_budget"`    // the bounded worklist the substrate ran at
	Model          string  `json:"model,omitempty"` // the agent's LLM (honest provenance)
	RealTotal      int     `json:"real_total"`
	EngineFound    int     `json:"engine_found"` // the bounded substrate — the floor
	AgentFound     int     `json:"agent_found"`  // the L2 agent
	Invented       int     `json:"invented"`
	Score          float64 `json:"score"`          // L2Scorecard accuracy (grounded ? recall : 0)
	Grade          string  `json:"grade"`          // STRONG | ADEQUATE | WEAK | DISQUALIFIED
	Discriminating bool    `json:"discriminating"` // did the run actually evaluate the agent?
	LiftPaths      int     `json:"lift_paths"`
	VerifiedRate   float64 `json:"verified_rate"` // remediation: verified fixes / confirmed
}

// CloudEngineEntry builds a ledger entry from the graded L2 scorecard + remediation of one run. TS is
// stamped by the caller (wall clock lives outside this pure helper, mirroring the other ledgers).
func CloudEngineEntry(seed int64, scaleBudget int, model string, sc L2Scorecard, rem RemediationScore) CloudEngineLedgerEntry {
	return CloudEngineLedgerEntry{
		Seed: seed, ScaleBudget: scaleBudget, Model: model,
		RealTotal: sc.RealTotal, EngineFound: sc.EngineFound, AgentFound: sc.AgentFound, Invented: sc.Invented,
		Score: sc.Score, Grade: sc.Grade(), Discriminating: sc.Discriminating, LiftPaths: sc.LiftPaths,
		VerifiedRate: rem.VerifiedRate,
	}
}

// AppendCloudEngineLedger appends one entry as a JSON line (O_APPEND — history accumulates, diffable, a
// crash mid-run loses nothing). Creates the parent dir + file if absent.
func AppendCloudEngineLedger(path string, e CloudEngineLedgerEntry) error {
	if strings.TrimSpace(path) == "" {
		return fmt.Errorf("empty ledger path")
	}
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	line, err := json.Marshal(e)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644) //nolint:gosec // caller-controlled bench path
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write(append(line, '\n'))
	return err
}

// LoadCloudEngineLedger reads every entry, skipping blank/corrupt lines best-effort.
func LoadCloudEngineLedger(path string) ([]CloudEngineLedgerEntry, error) {
	f, err := os.Open(path) //nolint:gosec // caller-controlled bench path
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []CloudEngineLedgerEntry
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var e CloudEngineLedgerEntry
		if json.Unmarshal([]byte(line), &e) == nil {
			out = append(out, e)
		}
	}
	return out, sc.Err()
}

// CloudEngineSummary is the tuning-trend roll-up over the DISCRIMINATING runs (the ones that actually
// evaluated the agent). A non-discriminating run is counted separately but excluded from the agent score —
// it measured the substrate, not L2 (§14 anti-overfit: don't let free 100%s inflate the agent's number).
type CloudEngineSummary struct {
	Runs            int     `json:"runs"`
	Discriminating  int     `json:"discriminating"` // runs that actually evaluated the agent
	Grounded        int     `json:"grounded"`       // of the discriminating runs, how many invented nothing
	MedianScore     float64 `json:"median_score"`   // median L2 score over discriminating runs
	BestScore       float64 `json:"best_score"`
	AvgLift         float64 `json:"avg_lift"`          // mean lift over discriminating runs
	AvgVerifiedRate float64 `json:"avg_verified_rate"` // mean remediation verified_rate over discriminating runs
}

// SummarizeCloudEngineLedger rolls the log into the tuning trend.
func SummarizeCloudEngineLedger(entries []CloudEngineLedgerEntry) CloudEngineSummary {
	s := CloudEngineSummary{Runs: len(entries)}
	scores := []float64{}
	var liftSum, verSum float64
	for _, e := range entries {
		if !e.Discriminating {
			continue
		}
		s.Discriminating++
		if e.Invented == 0 {
			s.Grounded++
		}
		scores = append(scores, e.Score)
		if e.Score > s.BestScore {
			s.BestScore = e.Score
		}
		liftSum += float64(e.LiftPaths)
		verSum += e.VerifiedRate
	}
	if len(scores) > 0 {
		sort.Float64s(scores)
		s.MedianScore = scores[len(scores)/2]
		s.AvgLift = liftSum / float64(len(scores))
		s.AvgVerifiedRate = verSum / float64(len(scores))
	}
	return s
}

// RenderCloudEngineLedger renders the durable L2 tuning scoreboard.
func RenderCloudEngineLedger(entries []CloudEngineLedgerEntry) string {
	s := SummarizeCloudEngineLedger(entries)
	var b strings.Builder
	b.WriteString("=== AI Cloud Engineer — L2 head-to-head ledger (durable, append-only) ===\n")
	fmt.Fprintf(&b, "runs: %d  ·  discriminating (actually evaluated the agent): %d  ·  grounded: %d/%d\n",
		s.Runs, s.Discriminating, s.Grounded, s.Discriminating)
	if s.Discriminating == 0 {
		b.WriteString("no discriminating runs yet — run the agent on a scenario with headroom (--discrimination-sweep to find one).\n")
		return b.String()
	}
	fmt.Fprintf(&b, "L2 score over discriminating runs: median %.2f, best %.2f  ·  avg lift +%.1f path(s)  ·  avg remediation verified_rate %.0f%%\n",
		s.MedianScore, s.BestScore, s.AvgLift, s.AvgVerifiedRate*100)
	return b.String()
}
