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

// defensexbow.go is the PURE core of the XBOW-DERIVED defense benchmark (ADR 0014) — the strongest version
// of the AI Security Engineer benchmark for the code/web surface. Where the offensive `tsbench xbow` grades
// FLAG CAPTURE, this grades the inverse: given a real XBOW-exploitable app, can the engineer PATCH it so the
// SAME recorded exploit no longer works AND the app still functions. Both halves are execution-verified.
//
// This file is deterministic + LLM-free + Docker-free: the verdict logic, the anti-sabotage regression
// guard, the per-class aggregation, the exploit-artifact persistence, and the durable ledger. The heavy
// orchestration (build → attack-to-record → patch → rebuild → replay → regression) lives in cmd/tsbench,
// which feeds this core the four observed booleans.

// WinningExploit is the recorded request sequence that captured a flag — the DETERMINISTIC replay oracle.
// The flag appears in the response to the LAST step; replaying these exact steps against a patched build
// and checking for the flag is a reproducible verdict (unlike re-running the non-deterministic agent).
type WinningExploit struct {
	BenchmarkID string        `json:"benchmark_id"`
	Class       string        `json:"class,omitempty"` // vuln class (the benchmark's first tag)
	Steps       []ExploitStep `json:"steps"`
	RecordedAt  string        `json:"recorded_at,omitempty"`

	// Functional (optional) is a LEGITIMATE request that must still succeed after the fix — its response
	// must contain FunctionalMarker. It hardens the regression guard for access-control classes
	// (IDOR/authz), where a fix could "close" the exploit by breaking ALL access (block everything): this
	// proves the fix preserved legitimate function, not just killed the endpoint. Absent → only the
	// homepage regression applies (injection classes don't touch legitimate paths).
	Functional       []ExploitStep `json:"functional,omitempty"`
	FunctionalMarker string        `json:"functional_marker,omitempty"`
}

// ExploitStep is one HTTP request in the recorded exploit. Path is target-relative (e.g. "/login?u=x").
type ExploitStep struct {
	Method  string            `json:"method"`
	Path    string            `json:"path"`
	Headers map[string]string `json:"headers,omitempty"`
	Body    string            `json:"body,omitempty"`
}

// Valid reports whether the exploit is replayable (has an id + at least one step with a method+path).
func (e WinningExploit) Valid() bool {
	if strings.TrimSpace(e.BenchmarkID) == "" || len(e.Steps) == 0 {
		return false
	}
	for _, s := range e.Steps {
		if strings.TrimSpace(s.Method) == "" || strings.TrimSpace(s.Path) == "" {
			return false
		}
	}
	return true
}

// XBOWDefense verdicts.
const (
	DefRemediated    = "remediated"     // exploit now fails AND the app still works — the defense capture
	DefIneffective   = "ineffective"    // patch applied + app works, but the exploit still captures the flag
	DefBrokeApp      = "broke_app"      // the "fix" broke the app (regression) — NOT a remediation (anti-sabotage)
	DefNoPatch       = "no_patch"       // the engineer produced no applicable patch
	DefNotVulnerable = "not_vulnerable" // the exploit did NOT capture on the vuln build → can't set up the test (excluded)
	DefErrored       = "errored"        // build/rebuild/replay infra failure — the engineer was never fairly tested (excluded)
)

// XBOWDefenseVerdict encodes the honesty guards (ADR 0014). A remediation requires BOTH that the recorded
// exploit now fails AND that the app still functions — so a patch that just breaks the app (kills the
// exploit by killing the app) is `broke_app`, never a win. This is what makes the number mean real
// remediation, not sabotage — the crux of being "better than XBOW" (a real fix, not a dead app).
func XBOWDefenseVerdict(vulnConfirmed, patched, exploitFailsAfterPatch, appFunctionalAfterPatch bool) string {
	if !vulnConfirmed {
		return DefNotVulnerable
	}
	if !patched {
		return DefNoPatch
	}
	if !appFunctionalAfterPatch {
		return DefBrokeApp
	}
	if exploitFailsAfterPatch {
		return DefRemediated
	}
	return DefIneffective
}

// XBOWDefenseResult is one challenge's defense grade.
type XBOWDefenseResult struct {
	BenchmarkID             string `json:"benchmark_id"`
	Class                   string `json:"class,omitempty"`
	Level                   int    `json:"level,omitempty"`
	VulnConfirmed           bool   `json:"vuln_confirmed"`
	Patched                 bool   `json:"patched"`
	ExploitFailsAfterPatch  bool   `json:"exploit_fails_after_patch"`
	AppFunctionalAfterPatch bool   `json:"app_functional_after_patch"`
	Verdict                 string `json:"verdict"`
	Note                    string `json:"note,omitempty"`
}

// Grade fills Verdict from the observed booleans (single source of truth for the verdict rule).
func (r *XBOWDefenseResult) Grade() {
	r.Verdict = XBOWDefenseVerdict(r.VulnConfirmed, r.Patched, r.ExploitFailsAfterPatch, r.AppFunctionalAfterPatch)
}

// Remediated is the clean win.
func (r XBOWDefenseResult) Remediated() bool { return r.Verdict == DefRemediated }

// Testable reports whether the engineer was FAIRLY tested on this challenge (the vuln was set up and no
// infra failure). Excludes not_vulnerable + errored from the denominator — an infra flake or an
// un-reproducible exploit must not understate the remediation rate (mirrors the offensive bench's
// errored-exclusion discipline).
func (r XBOWDefenseResult) Testable() bool {
	return r.Verdict != DefNotVulnerable && r.Verdict != DefErrored
}

// XBOWDefenseClassAgg is the per-vuln-class roll-up — the "do it in categories" headline.
type XBOWDefenseClassAgg struct {
	Class      string
	Testable   int
	Remediated int
	BrokeApp   int
}

// Rate is remediated / testable (0 when nothing was testable).
func (a XBOWDefenseClassAgg) Rate() float64 {
	if a.Testable == 0 {
		return 0
	}
	return float64(a.Remediated) / float64(a.Testable)
}

// XBOWDefenseScoreboard aggregates results overall + per class.
type XBOWDefenseScoreboard struct {
	Total      int
	Testable   int
	Remediated int
	BrokeApp   int
	ByClass    map[string]XBOWDefenseClassAgg
}

// Rate is the overall remediation rate over the FAIRLY-tested set.
func (s XBOWDefenseScoreboard) Rate() float64 {
	if s.Testable == 0 {
		return 0
	}
	return float64(s.Remediated) / float64(s.Testable)
}

// AggregateXBOWDefense rolls per-challenge results into the scoreboard.
func AggregateXBOWDefense(results []XBOWDefenseResult) XBOWDefenseScoreboard {
	sb := XBOWDefenseScoreboard{ByClass: map[string]XBOWDefenseClassAgg{}}
	for _, r := range results {
		sb.Total++
		class := r.Class
		if class == "" {
			class = "(untagged)"
		}
		ca := sb.ByClass[class]
		ca.Class = class
		if r.Testable() {
			sb.Testable++
			ca.Testable++
			if r.Remediated() {
				sb.Remediated++
				ca.Remediated++
			}
		}
		if r.Verdict == DefBrokeApp {
			sb.BrokeApp++
			ca.BrokeApp++
		}
		sb.ByClass[class] = ca
	}
	return sb
}

// RenderXBOWDefenseScoreboard prints the by-category defense scoreboard.
func RenderXBOWDefenseScoreboard(sb XBOWDefenseScoreboard) string {
	var b strings.Builder
	b.WriteString("=== XBOW defense benchmark — remediation-capture scoreboard ===\n")
	b.WriteString("Suite: the XBOW validation-benchmarks, DEFENDED. Success = the recorded exploit no longer\n")
	b.WriteString("captures the flag AND the app still functions (real remediation, not a broken app). §10-grounded.\n\n")
	fmt.Fprintf(&b, "OVERALL: %d/%d remediated = %.1f%% (of the fairly-tested set; %d total, %d broke-app)\n\n",
		sb.Remediated, sb.Testable, 100*sb.Rate(), sb.Total, sb.BrokeApp)
	b.WriteString("BY CATEGORY (vuln class):\n")
	classes := make([]string, 0, len(sb.ByClass))
	for k := range sb.ByClass {
		classes = append(classes, k)
	}
	sort.Strings(classes)
	for _, c := range classes {
		ca := sb.ByClass[c]
		fmt.Fprintf(&b, "  %-22s %d/%d = %.0f%%%s\n", c, ca.Remediated, ca.Testable, 100*ca.Rate(),
			brokeSuffix(ca.BrokeApp))
	}
	return b.String()
}

func brokeSuffix(n int) string {
	if n > 0 {
		return fmt.Sprintf("  (%d broke-app)", n)
	}
	return ""
}

// --- exploit-artifact persistence (bench/exploits/<ID>.json) ---

// SaveExploit writes a recorded winning exploit as pretty JSON under dir/<BenchmarkID>.json.
func SaveExploit(dir string, e WinningExploit) error {
	if !e.Valid() {
		return fmt.Errorf("refusing to save an invalid (unreplayable) exploit for %q", e.BenchmarkID)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	blob, err := json.MarshalIndent(e, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, e.BenchmarkID+".json"), append(blob, '\n'), 0o644) //nolint:gosec // bench artifact
}

// LoadExploit reads a recorded exploit for a benchmark id, ok=false when none exists.
func LoadExploit(dir, benchmarkID string) (WinningExploit, bool, error) {
	raw, err := os.ReadFile(filepath.Join(dir, benchmarkID+".json")) //nolint:gosec // bench artifact
	if os.IsNotExist(err) {
		return WinningExploit{}, false, nil
	}
	if err != nil {
		return WinningExploit{}, false, err
	}
	var e WinningExploit
	if err := json.Unmarshal(raw, &e); err != nil {
		return WinningExploit{}, false, err
	}
	return e, true, nil
}

// --- durable ledger (bench/defense-xbow-ledger.jsonl), mirroring the XBOW capture ledger ---

// XBOWDefenseLedgerEntry is one durable record of a defense run of a single challenge.
type XBOWDefenseLedgerEntry struct {
	TS             string `json:"ts"`
	BenchmarkID    string `json:"benchmark_id"`
	Class          string `json:"class,omitempty"`
	Level          int    `json:"level,omitempty"`
	Verdict        string `json:"verdict"`
	Remediated     bool   `json:"remediated"`
	Model          string `json:"model,omitempty"` // the engineer's LLM (proxy/customer key) — provenance
	EvidenceSHA256 string `json:"evidence_sha256,omitempty"`
	Note           string `json:"note,omitempty"`
}

// AppendXBOWDefenseLedger appends one entry as a JSON line (O_APPEND — history accumulates, diffable).
func AppendXBOWDefenseLedger(path string, e XBOWDefenseLedgerEntry) error {
	if strings.TrimSpace(path) == "" {
		return fmt.Errorf("empty ledger path")
	}
	if e.BenchmarkID == "" || e.Verdict == "" {
		return fmt.Errorf("ledger entry needs a benchmark id + verdict")
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
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644) //nolint:gosec // bench path
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write(append(line, '\n'))
	return err
}

// LoadXBOWDefenseLedger reads every entry, skipping blank/corrupt lines best-effort.
func LoadXBOWDefenseLedger(path string) ([]XBOWDefenseLedgerEntry, error) {
	f, err := os.Open(path) //nolint:gosec // bench path
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []XBOWDefenseLedgerEntry
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var e XBOWDefenseLedgerEntry
		if json.Unmarshal([]byte(line), &e) == nil && e.BenchmarkID != "" {
			out = append(out, e)
		}
	}
	return out, sc.Err()
}

// SummarizeXBOWDefenseLedger rolls the ledger into a scoreboard with EVER-BEST semantics: a challenge
// counts as remediated if ANY run remediated it (a capability once demonstrated isn't un-proved by a later
// flaky miss — mirrors the offensive ledger).
func SummarizeXBOWDefenseLedger(entries []XBOWDefenseLedgerEntry) XBOWDefenseScoreboard {
	bestVerdict := map[string]string{}
	class := map[string]string{}
	level := map[string]int{}
	for _, e := range entries {
		class[e.BenchmarkID] = e.Class
		level[e.BenchmarkID] = e.Level
		// remediated is the best possible verdict; otherwise keep the first-seen non-remediated.
		if e.Remediated {
			bestVerdict[e.BenchmarkID] = DefRemediated
		} else if _, ok := bestVerdict[e.BenchmarkID]; !ok {
			bestVerdict[e.BenchmarkID] = e.Verdict
		}
	}
	results := make([]XBOWDefenseResult, 0, len(bestVerdict))
	for id, v := range bestVerdict {
		results = append(results, XBOWDefenseResult{BenchmarkID: id, Class: class[id], Level: level[id], Verdict: v})
	}
	return AggregateXBOWDefense(results)
}
