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
