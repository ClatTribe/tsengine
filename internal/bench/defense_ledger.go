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

// defense_ledger.go is the DEFENSIVE capture record — the durable, append-only twin of the XBOW ledger,
// for the AI Security Engineer instead of the pentester. XBOW's ledger answers "how many flags have we
// EVER captured"; this answers "how much of a seeded estate have we EVER verifiably remediated". Same
// discipline: one appended JSON line per scenario run (substrate OR agent mode), git-committed + diffable,
// each grounded by an evidence SHA-256 (§10), never overwritten — so the defensive number is a real
// artifact, not a slogan. The MODE field is load-bearing: the substrate-vs-agent delta is the measured
// lift of the LLM engineer over deterministic remediation (§14.1 ablation discipline).

// DefenseLedgerEntry is one durable record of a single scenario run.
type DefenseLedgerEntry struct {
	TS              string  `json:"ts"`                        // RFC3339 UTC — lexicographic order == chronological
	ScenarioID      string  `json:"scenario_id"`               //
	Name            string  `json:"name,omitempty"`            //
	Mode            string  `json:"mode"`                      // "substrate" (deterministic remediate.Propose) | "agent" (LLM engineer)
	Closeable       int     `json:"closeable"`                 //
	Captured        int     `json:"captured"`                  //
	RemediationRate float64 `json:"remediation_rate"`          //
	ExpectedPaths   int     `json:"expected_paths"`            //
	FoundPaths      int     `json:"found_paths"`               //
	DecoyActions    int     `json:"decoy_actions"`             //
	Invented        int     `json:"invented"`                  //
	Pass            bool    `json:"pass"`                      //
	EvidenceSHA256  string  `json:"evidence_sha256,omitempty"` // fingerprint of the graded score blob
	Note            string  `json:"note,omitempty"`            //
}

// FromScore builds a ledger entry from a graded score (TS + evidence-sha are stamped by the caller — wall
// clock + hashing live outside this pure helper, mirroring the XBOW ledger).
func DefenseEntryFromScore(s DefenseScore, name, mode string) DefenseLedgerEntry {
	return DefenseLedgerEntry{
		ScenarioID: s.ScenarioID, Name: name, Mode: mode,
		Closeable: s.Closeable, Captured: s.Captured, RemediationRate: s.RemediationRate,
		ExpectedPaths: s.ExpectedPaths, FoundPaths: s.FoundPaths,
		DecoyActions: s.DecoyActions, Invented: len(s.Invented), Pass: s.Pass(),
	}
}

// AppendDefenseLedger appends one entry as a JSON line (O_APPEND — history accumulates, stays diffable,
// a crash mid-run loses nothing). Creates the parent dir + file if absent.
func AppendDefenseLedger(path string, e DefenseLedgerEntry) error {
	if strings.TrimSpace(path) == "" {
		return fmt.Errorf("empty ledger path")
	}
	if e.ScenarioID == "" {
		return fmt.Errorf("ledger entry has no scenario id")
	}
	if e.Mode == "" {
		return fmt.Errorf("ledger entry has no mode (substrate|agent)")
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

// LoadDefenseLedger reads every entry, skipping blank/corrupt lines best-effort.
func LoadDefenseLedger(path string) ([]DefenseLedgerEntry, error) {
	f, err := os.Open(path) //nolint:gosec // caller-controlled bench path
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []DefenseLedgerEntry
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var e DefenseLedgerEntry
		if json.Unmarshal([]byte(line), &e) == nil && e.ScenarioID != "" {
			out = append(out, e)
		}
	}
	return out, sc.Err()
}

// DefenseModeSummary is the best-ever roll-up for ONE mode (substrate or agent): the best remediation rate
// each scenario has EVER achieved, and how many scenarios that mode has cleanly PASSED.
type DefenseModeSummary struct {
	Mode     string
	Runs     int
	Passed   int                // distinct scenarios ever PASS-ed in this mode
	BestRate map[string]float64 // best remediation rate per scenario
	BestPath map[string]float64 // best path recall per scenario (found/expected)
}

// SummarizeDefenseLedger rolls the log into per-mode best-ever summaries — the honest "where we stand"
// with ever-best semantics (a capability once demonstrated isn't un-proved by a later flaky miss),
// keeping substrate and agent SEPARATE so the ablation delta is legible.
func SummarizeDefenseLedger(entries []DefenseLedgerEntry) map[string]DefenseModeSummary {
	out := map[string]DefenseModeSummary{}
	passedSeen := map[string]map[string]bool{} // mode → scenario → ever-passed
	for _, e := range entries {
		m, ok := out[e.Mode]
		if !ok {
			m = DefenseModeSummary{Mode: e.Mode, BestRate: map[string]float64{}, BestPath: map[string]float64{}}
			passedSeen[e.Mode] = map[string]bool{}
		}
		m.Runs++
		if e.RemediationRate > m.BestRate[e.ScenarioID] {
			m.BestRate[e.ScenarioID] = e.RemediationRate
		}
		var pr float64 = 1.0
		if e.ExpectedPaths > 0 {
			pr = float64(e.FoundPaths) / float64(e.ExpectedPaths)
		}
		if pr > m.BestPath[e.ScenarioID] {
			m.BestPath[e.ScenarioID] = pr
		}
		if e.Pass && !passedSeen[e.Mode][e.ScenarioID] {
			passedSeen[e.Mode][e.ScenarioID] = true
			m.Passed++
		}
		out[e.Mode] = m
	}
	return out
}

// RenderDefenseLedgerMarkdown renders the durable defensive scoreboard: the headline remediation-capture
// per mode, the substrate→agent lift, and a per-scenario best-rate table.
func RenderDefenseLedgerMarkdown(entries []DefenseLedgerEntry) string {
	byMode := SummarizeDefenseLedger(entries)
	var b strings.Builder
	b.WriteString("# Defensive remediation-capture ledger (durable, append-only)\n\n")
	b.WriteString("_Generated from `bench/defense-ledger.jsonl` — one appended line per scenario run of `tsbench defense`. ")
	b.WriteString("The DEFENSIVE twin of the XBOW ledger: XBOW scores exploitation (flags captured); this scores ")
	b.WriteString("remediation (seeded vulns verifiably closed on re-scan, via the SAME `retest.Verify` the product uses). ")
	b.WriteString("Substrate (deterministic) and agent (LLM engineer) are kept separate — the delta is the agent's measured lift._\n\n")

	// Headline per mode + the ablation delta on any shared scenario.
	sub, hasSub := byMode["substrate"]
	agt, hasAgt := byMode["agent"]
	if hasSub {
		fmt.Fprintf(&b, "- **substrate** (deterministic remediation): %d scenario(s) fully remediated, %d run(s).\n", sub.Passed, sub.Runs)
	}
	if hasAgt {
		fmt.Fprintf(&b, "- **agent** (AI Security Engineer): %d scenario(s) fully remediated, %d run(s).\n", agt.Passed, agt.Runs)
	}
	if hasSub && hasAgt {
		b.WriteString("\n## Agent lift (substrate → agent), per scenario\n\n| Scenario | Substrate rate | Agent rate | Lift |\n|---|---|---|---|\n")
		ids := sortedScenarioIDs(sub.BestRate, agt.BestRate)
		for _, id := range ids {
			s, a := sub.BestRate[id], agt.BestRate[id]
			fmt.Fprintf(&b, "| %s | %.0f%% | %.0f%% | %+.0f%% |\n", id, s*100, a*100, (a-s)*100)
		}
	}

	// Per-mode best-rate tables.
	for _, mode := range []string{"substrate", "agent"} {
		m, ok := byMode[mode]
		if !ok {
			continue
		}
		fmt.Fprintf(&b, "\n## %s — best remediation rate per scenario\n\n| Scenario | Best remediation | Best path recall |\n|---|---|---|\n", mode)
		ids := make([]string, 0, len(m.BestRate))
		for id := range m.BestRate {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		for _, id := range ids {
			fmt.Fprintf(&b, "| %s | %.0f%% | %.0f%% |\n", id, m.BestRate[id]*100, m.BestPath[id]*100)
		}
	}
	return b.String()
}

func sortedScenarioIDs(a, b map[string]float64) []string {
	seen := map[string]bool{}
	var out []string
	for id := range a {
		if !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	for id := range b {
		if !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	sort.Strings(out)
	return out
}
