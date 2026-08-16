package bench

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/ClatTribe/tsengine/pkg/types"
)

func TestLoadSastCases(t *testing.T) {
	csv := "# test name, category, real vulnerability, cwe, Benchmark version: 1.2\n" +
		"BenchmarkTest00001,pathtraver,true,22\n" +
		"BenchmarkTest00002,sqli,false,89\n"
	p := filepath.Join(t.TempDir(), "expectedresults.csv")
	if err := os.WriteFile(p, []byte(csv), 0o600); err != nil {
		t.Fatal(err)
	}
	cases, err := LoadSastCases(p)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(cases) != 2 {
		t.Fatalf("want 2 cases (header skipped), got %d", len(cases))
	}
	if cases[0].Name != "BenchmarkTest00001" || cases[0].Category != "pathtraver" || !cases[0].Vulnerable {
		t.Errorf("row0 mis-parsed: %+v", cases[0])
	}
	if cases[1].Vulnerable {
		t.Errorf("row1 should be non-vulnerable: %+v", cases[1])
	}
}

func TestScoreSast_ConfusionMatrix(t *testing.T) {
	cases := []SastCase{
		{Name: "BenchmarkTest00001", Category: "sqli", Vulnerable: true},  // flagged → TP
		{Name: "BenchmarkTest00002", Category: "sqli", Vulnerable: false}, // not flagged → TN
		{Name: "BenchmarkTest00003", Category: "sqli", Vulnerable: true},  // not flagged → FN
		{Name: "BenchmarkTest00004", Category: "sqli", Vulnerable: false}, // flagged → FP
	}
	scan := &types.Scan{FindingsRaw: []types.Finding{
		{Tool: "semgrep", CWE: []string{"CWE-89"}, Endpoint: "src/BenchmarkTest00001.java:42"},
		{Tool: "semgrep", CWE: []string{"CWE-89"}, Endpoint: "src/BenchmarkTest00004.java:7"},
		// a finding with no category-mapped CWE must not affect scoring:
		{Tool: "semgrep", CWE: []string{"CWE-1234"}, Endpoint: "src/BenchmarkTest00001.java:99"},
	}}
	rep := ScoreSast(cases, scan)
	sqli := rep.PerCategory["sqli"]
	if sqli == nil {
		t.Fatal("no sqli category")
	}
	if sqli.TP != 1 || sqli.FP != 1 || sqli.TN != 1 || sqli.FN != 1 {
		t.Errorf("confusion matrix = TP%d FP%d TN%d FN%d, want 1/1/1/1", sqli.TP, sqli.FP, sqli.TN, sqli.FN)
	}
	if y := sqli.Youden(); y > 0.001 || y < -0.001 { // tpr .5 - fpr .5 = 0
		t.Errorf("Youden = %v, want ~0", y)
	}
	if rep.Overall.TP != 1 || rep.Overall.FN != 1 {
		t.Errorf("overall rollup wrong: %+v", rep.Overall)
	}
	if rep.Competitors.Leaderboard == "" {
		t.Error("report must carry the competitor citation")
	}
}

// TestScoreSast_GradesRawAndDeliveredIndependently pins the two-audience scoring.
//
// The bench used to grade FindingsRaw only, which made §14.1's documented L1.5 ablation inert here:
// TSENGINE_L15_DISABLED could not move a number computed from the set captured before hook 1 runs.
// So the FP filter could demote 577 findings on a real run and the scorecard would look identical.
//
// The fixture is deliberately asymmetric — the enriched set drops the false positive and keeps the
// true one, i.e. L1.5 doing its job. A regression that scored Delivered from FindingsRaw would give
// both sets FP=1 and fail on the lift assertion.
func TestScoreSast_GradesRawAndDeliveredIndependently(t *testing.T) {
	cases := []SastCase{
		{Name: "BenchmarkTest00001", Category: "sqli", Vulnerable: true},
		{Name: "BenchmarkTest00004", Category: "sqli", Vulnerable: false},
	}
	scan := &types.Scan{
		FindingsRaw: []types.Finding{
			{Tool: "semgrep", CWE: []string{"CWE-89"}, Endpoint: "src/BenchmarkTest00001.java:42"},
			{Tool: "semgrep", CWE: []string{"CWE-89"}, Endpoint: "src/BenchmarkTest00004.java:7"},
		},
		// The L1.5 chain dropped the finding on the non-vulnerable case.
		FindingsEnriched: []types.Finding{
			{Tool: "semgrep", CWE: []string{"CWE-89"}, Endpoint: "src/BenchmarkTest00001.java:42"},
		},
	}
	rep := ScoreSast(cases, scan)

	if rep.Overall.TP != 1 || rep.Overall.FP != 1 {
		t.Errorf("raw should keep the false positive: %+v", rep.Overall)
	}
	if rep.Delivered.TP != 1 || rep.Delivered.FP != 0 || rep.Delivered.TN != 1 {
		t.Errorf("delivered should reflect the L1.5 drop: %+v", rep.Delivered)
	}
	if lift := rep.L15Lift(); lift <= 0 {
		t.Errorf("L15Lift = %+.2f, want positive when the chain removes a false positive.\n"+
			"If this is 0, Delivered is being scored from the same set as Overall and the "+
			"ablation is inert again.", lift)
	}
}

// CWE-326 (inadequate encryption strength, e.g. DES) is a sibling of CWE-327 and is what
// semgrep emits for the OWASP-Benchmark crypto cases — it must score under "crypto", else
// real crypto detections are silently discarded by the scorer (the crypto-0% bug).
func TestScoreSast_Crypto326MapsToCrypto(t *testing.T) {
	cases := []SastCase{
		{Name: "BenchmarkTest10001", Category: "crypto", Vulnerable: true},  // DES → flagged → TP
		{Name: "BenchmarkTest10002", Category: "crypto", Vulnerable: false}, // AES → not flagged → TN
	}
	scan := &types.Scan{FindingsRaw: []types.Finding{
		{Tool: "semgrep", CWE: []string{"CWE-326"}, Endpoint: "src/BenchmarkTest10001.java:12"},
	}}
	c := ScoreSast(cases, scan).PerCategory["crypto"]
	if c == nil || c.TP != 1 || c.TN != 1 || c.FP != 0 || c.FN != 0 {
		t.Fatalf("CWE-326 must count as a crypto hit: got %+v", c)
	}
}

func TestSastCaseFlagged_NoSubstringCollision(t *testing.T) {
	// BenchmarkTest00004 must NOT be flagged by a finding on …00040.
	c := SastCase{Name: "BenchmarkTest00004", Category: "sqli", Vulnerable: true}
	if sastCaseFlagged(c, []string{"src/BenchmarkTest00040.java:1"}) {
		t.Error("00004 should not match 00040 (boundary via trailing dot)")
	}
	if !sastCaseFlagged(c, []string{"src/BenchmarkTest00004.java:1"}) {
		t.Error("00004 should match its own file")
	}
}
