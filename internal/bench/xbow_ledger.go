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

// xbow_ledger.go is the DURABLE, append-only capture record — the audit trail the ephemeral `--out`
// snapshot never gave. Before this, every XBOW run wrote a `--out` snapshot that got overwritten when the
// path was reused and lived in a scratch dir that was cleaned for disk, so a campaign's capture count
// survived only as a narrative claim (and drifted from what was reproducible on disk). The ledger fixes
// that: every run (solved / miss / errored) appends ONE JSON line to a git-committed `.jsonl`, so the
// number is a verifiable, diffable artifact and no success is ever silently lost.

// XBOWLedgerEntry is one durable record of a single benchmark run. EvidenceSHA256 fingerprints the exact
// evidence blob the flag-capture check ran over, so a SOLVED entry is tamper-evident and tied to a real
// artifact (§10) — without leaking the build-time random flag. TS/ImageDigest are stamped by the caller
// (wall-clock + `docker inspect` live outside this pure package).
type XBOWLedgerEntry struct {
	TS             string   `json:"ts"` // RFC3339 UTC — lexicographic order == chronological
	ID             string   `json:"id"`
	Name           string   `json:"name,omitempty"`
	Level          int      `json:"level"`
	Tags           []string `json:"tags,omitempty"`
	Mode           string   `json:"mode"` // investigate | scan
	Solved         bool     `json:"solved"`
	Findings       int      `json:"findings"`
	Errored        bool     `json:"errored,omitempty"`
	EvidenceSHA256 string   `json:"evidence_sha256,omitempty"`
	ImageDigest    string   `json:"image_digest,omitempty"`
	Backfilled     bool     `json:"backfilled,omitempty"` // reconstructed from a surviving run snapshot, not a live grade
	Note           string   `json:"note,omitempty"`
}

// AppendXBOWLedger appends one entry as a JSON line (O_APPEND — never rewrites, so history accumulates,
// stays git-diffable, and a crash mid-campaign loses nothing). Creates the parent dir + file if absent.
func AppendXBOWLedger(path string, e XBOWLedgerEntry) error {
	if strings.TrimSpace(path) == "" {
		return fmt.Errorf("empty ledger path")
	}
	if e.ID == "" {
		return fmt.Errorf("ledger entry has no benchmark id")
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

// LoadXBOWLedger reads every entry. A blank or corrupt line is skipped best-effort — one bad append never
// voids the whole campaign log.
func LoadXBOWLedger(path string) ([]XBOWLedgerEntry, error) {
	f, err := os.Open(path) //nolint:gosec // caller-controlled bench path
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []XBOWLedgerEntry
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var e XBOWLedgerEntry
		if json.Unmarshal([]byte(line), &e) == nil && e.ID != "" {
			out = append(out, e)
		}
	}
	return out, sc.Err()
}

// XBOWLedgerSummary is the auditable roll-up: which DISTINCT benchmarks were EVER captured (a flag once
// captured proves the capability — a later flaky miss doesn't un-prove it), broken out by vuln class and
// difficulty level, each capture citing its first proving run.
type XBOWLedgerSummary struct {
	Runs         int
	DistinctRun  int
	Captured     []string                   // distinct ids EVER solved (sorted)
	ByTag        map[string]int             // captured count per vuln class (first tag)
	ByLevel      map[int]int                // captured count per difficulty level
	FirstCapture map[string]XBOWLedgerEntry // earliest solved entry per id — the citable proof
}

// SummarizeXBOWLedger rolls the append-only log into the capture summary with ever-solved semantics: an
// id counts as captured if ANY run solved it, and the FIRST solved run is cited as the proof (its
// evidence sha + timestamp).
func SummarizeXBOWLedger(entries []XBOWLedgerEntry) XBOWLedgerSummary {
	s := XBOWLedgerSummary{ByTag: map[string]int{}, ByLevel: map[int]int{}, FirstCapture: map[string]XBOWLedgerEntry{}}
	ids := map[string]bool{}
	for _, e := range entries {
		s.Runs++
		ids[e.ID] = true
		if !e.Solved {
			continue
		}
		if prev, seen := s.FirstCapture[e.ID]; !seen || e.TS < prev.TS {
			s.FirstCapture[e.ID] = e
		}
	}
	s.DistinctRun = len(ids)
	for id, e := range s.FirstCapture {
		s.Captured = append(s.Captured, id)
		tag := "(untagged)"
		if len(e.Tags) > 0 {
			tag = e.Tags[0]
		}
		s.ByTag[tag]++
		s.ByLevel[e.Level]++
	}
	sort.Strings(s.Captured)
	return s
}

// RenderXBOWLedgerMarkdown renders the durable, committed capture scoreboard from the append-only ledger:
// the headline capture count, a per-class and per-level breakdown, and a per-benchmark proof table (id,
// class, level, first-captured timestamp, evidence-sha fingerprint). This is the "written number".
func RenderXBOWLedgerMarkdown(entries []XBOWLedgerEntry) string {
	s := SummarizeXBOWLedger(entries)
	var b strings.Builder
	b.WriteString("# XBOW flag-capture ledger (durable, append-only)\n\n")
	b.WriteString("_Generated from `bench/xbow-ledger.jsonl` — one appended line per run of `tsbench xbow`. ")
	b.WriteString("Every capture is grounded by an evidence SHA-256 (§10) and never overwritten. ")
	b.WriteString("Same-suite yardstick: XBOW (suite authors) publish their own solve-rate on these 104 challenges._\n\n")
	fmt.Fprintf(&b, "**%d distinct benchmarks captured** across %d run record(s) over %d distinct benchmark(s) attempted.\n\n",
		len(s.Captured), s.Runs, s.DistinctRun)

	// per-class
	b.WriteString("## Captured by vuln class\n\n| Class | Captured |\n|---|---|\n")
	classes := make([]string, 0, len(s.ByTag))
	for k := range s.ByTag {
		classes = append(classes, k)
	}
	sort.Strings(classes)
	for _, c := range classes {
		fmt.Fprintf(&b, "| %s | %d |\n", c, s.ByTag[c])
	}

	// per-level
	b.WriteString("\n## Captured by difficulty level\n\n| Level | Captured |\n|---|---|\n")
	levels := make([]int, 0, len(s.ByLevel))
	for k := range s.ByLevel {
		levels = append(levels, k)
	}
	sort.Ints(levels)
	for _, l := range levels {
		fmt.Fprintf(&b, "| %s | %d |\n", levelName(l), s.ByLevel[l])
	}

	// proof table
	b.WriteString("\n## Capture proofs (first proving run per benchmark)\n\n")
	b.WriteString("| Benchmark | Class | Level | First captured (UTC) | Evidence SHA-256 | Src |\n|---|---|---|---|---|---|\n")
	for _, id := range s.Captured {
		e := s.FirstCapture[id]
		tag := "—"
		if len(e.Tags) > 0 {
			tag = e.Tags[0]
		}
		sha := e.EvidenceSHA256
		if len(sha) > 16 {
			sha = sha[:16] + "…"
		}
		if sha == "" {
			sha = "—"
		}
		src := "live"
		if e.Backfilled {
			src = "backfill"
		}
		fmt.Fprintf(&b, "| %s | %s | %s | %s | `%s` | %s |\n", id, tag, levelName(e.Level), e.TS, sha, src)
	}
	return b.String()
}
