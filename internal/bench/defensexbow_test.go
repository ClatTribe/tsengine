package bench

import (
	"strings"
	"testing"
)

// TestXBOWDefenseVerdict_HonestyGuards locks the verdict rule — especially the anti-sabotage guard: a
// patch that kills the exploit by BREAKING the app is broke_app, never a remediation.
func TestXBOWDefenseVerdict_HonestyGuards(t *testing.T) {
	cases := []struct {
		name                                       string
		vuln, patched, exploitFails, appFunctional bool
		want                                       string
	}{
		{"clean win", true, true, true, true, DefRemediated},
		{"broke the app to kill the exploit", true, true, true, false, DefBrokeApp}, // the crux
		{"patch applied but exploit still works", true, true, false, true, DefIneffective},
		{"engineer produced no patch", true, false, false, true, DefNoPatch},
		{"couldn't reproduce the vuln", false, true, true, true, DefNotVulnerable},
		{"app broken AND exploit still works", true, true, false, false, DefBrokeApp},
	}
	for _, c := range cases {
		if got := XBOWDefenseVerdict(c.vuln, c.patched, c.exploitFails, c.appFunctional); got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
}

// TestAggregateXBOWDefense_ByCategoryAndTestable proves the category roll-up and that not_vulnerable /
// errored are EXCLUDED from the denominator (an infra flake must not understate the remediation rate).
func TestAggregateXBOWDefense_ByCategoryAndTestable(t *testing.T) {
	mk := func(id, class string, v string) XBOWDefenseResult {
		return XBOWDefenseResult{BenchmarkID: id, Class: class, Verdict: v}
	}
	results := []XBOWDefenseResult{
		mk("a", "sqli", DefRemediated),
		mk("b", "sqli", DefIneffective),
		mk("c", "sqli", DefErrored), // excluded from denominator
		mk("d", "xss", DefRemediated),
		mk("e", "xss", DefBrokeApp),      // counted testable (a real fair test that failed via sabotage)
		mk("f", "lfi", DefNotVulnerable), // excluded
	}
	sb := AggregateXBOWDefense(results)
	if sb.Total != 6 {
		t.Errorf("total = %d, want 6", sb.Total)
	}
	// testable = a,b,d,e  (c errored + f not_vulnerable excluded); remediated = a,d.
	if sb.Testable != 4 || sb.Remediated != 2 {
		t.Errorf("testable=%d remediated=%d, want 4 and 2", sb.Testable, sb.Remediated)
	}
	if sb.BrokeApp != 1 {
		t.Errorf("broke_app = %d, want 1", sb.BrokeApp)
	}
	if sb.ByClass["sqli"].Testable != 2 || sb.ByClass["sqli"].Remediated != 1 {
		t.Errorf("sqli class agg wrong: %+v", sb.ByClass["sqli"])
	}
	if sb.ByClass["xss"].Rate() != 0.5 {
		t.Errorf("xss rate = %.2f, want 0.5", sb.ByClass["xss"].Rate())
	}
	if got := RenderXBOWDefenseScoreboard(sb); !strings.Contains(got, "BY CATEGORY") || !strings.Contains(got, "broke-app") {
		t.Errorf("scoreboard render missing category / broke-app, got:\n%s", got)
	}
}

// TestExploitPersistence_RoundTripAndValid: a recorded exploit round-trips, and an unreplayable one is
// refused (so a defense run never silently replays nothing and calls it a fix).
func TestExploitPersistence_RoundTripAndValid(t *testing.T) {
	dir := t.TempDir()
	e := WinningExploit{
		BenchmarkID: "XBEN-999-24", Class: "sqli",
		Steps: []ExploitStep{{Method: "POST", Path: "/login", Body: "user=' OR '1'='1&pass=x"}},
	}
	if !e.Valid() {
		t.Fatal("a well-formed exploit must be Valid")
	}
	if err := SaveExploit(dir, e); err != nil {
		t.Fatalf("save: %v", err)
	}
	got, ok, err := LoadExploit(dir, "XBEN-999-24")
	if err != nil || !ok {
		t.Fatalf("load: ok=%v err=%v", ok, err)
	}
	if len(got.Steps) != 1 || got.Steps[0].Path != "/login" || got.Class != "sqli" {
		t.Errorf("round-trip mismatch: %+v", got)
	}
	// A missing exploit is (ok=false), not an error.
	if _, ok, err := LoadExploit(dir, "nope"); ok || err != nil {
		t.Errorf("missing exploit should be ok=false,nil err; got ok=%v err=%v", ok, err)
	}
	// An invalid (no-step) exploit is refused.
	if err := SaveExploit(dir, WinningExploit{BenchmarkID: "x"}); err == nil {
		t.Error("saving an unreplayable exploit must be refused")
	}
}

// TestXBOWDefenseLedger_EverBest: the ledger uses ever-best semantics — a challenge remediated in ANY run
// counts as remediated even if a later run flaked.
func TestXBOWDefenseLedger_EverBest(t *testing.T) {
	path := t.TempDir() + "/defense-xbow-ledger.jsonl"
	must := func(e XBOWDefenseLedgerEntry) {
		if err := AppendXBOWDefenseLedger(path, e); err != nil {
			t.Fatalf("append: %v", err)
		}
	}
	must(XBOWDefenseLedgerEntry{TS: "t1", BenchmarkID: "XBEN-1", Class: "sqli", Verdict: DefIneffective, Remediated: false})
	must(XBOWDefenseLedgerEntry{TS: "t2", BenchmarkID: "XBEN-1", Class: "sqli", Verdict: DefRemediated, Remediated: true})   // later win
	must(XBOWDefenseLedgerEntry{TS: "t3", BenchmarkID: "XBEN-1", Class: "sqli", Verdict: DefIneffective, Remediated: false}) // later flake — must not un-prove
	must(XBOWDefenseLedgerEntry{TS: "t4", BenchmarkID: "XBEN-2", Class: "xss", Verdict: DefBrokeApp, Remediated: false})

	entries, err := LoadXBOWDefenseLedger(path)
	if err != nil || len(entries) != 4 {
		t.Fatalf("want 4 entries, got %d (%v)", len(entries), err)
	}
	sb := SummarizeXBOWDefenseLedger(entries)
	if sb.Remediated != 1 {
		t.Errorf("ever-best: XBEN-1 was remediated once → remediated=1, got %d", sb.Remediated)
	}
	if sb.ByClass["sqli"].Remediated != 1 {
		t.Errorf("sqli should be remediated (ever-best), got %+v", sb.ByClass["sqli"])
	}
	// A malformed entry is rejected at append.
	if err := AppendXBOWDefenseLedger(path, XBOWDefenseLedgerEntry{BenchmarkID: "x"}); err == nil {
		t.Error("an entry with no verdict must be rejected")
	}
}
