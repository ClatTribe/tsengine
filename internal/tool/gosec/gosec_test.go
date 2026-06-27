package gosec

import (
	"testing"

	"github.com/ClatTribe/tsengine/pkg/types"
)

// A representative gosec -fmt=json run: a high-confidence SQLi (G201, CWE-89 → high), and a LOW-confidence
// high-severity weak-RNG (G404) that must be capped at medium (gosec's low-confidence highs are FP-prone).
const fixture = `{
  "Issues": [
    {"severity":"HIGH","confidence":"HIGH","cwe":{"id":"89"},"rule_id":"G201","details":"SQL string formatting","file":"/workspace/db.go","line":"42"},
    {"severity":"HIGH","confidence":"LOW","cwe":{"id":"338"},"rule_id":"G404","details":"Use of weak random number generator","file":"/workspace/rng.go","line":"7"}
  ],
  "Stats": {"files": 2, "found": 2}
}`

func TestParse_MapsSeverityCWEAndCapsLowConfidence(t *testing.T) {
	out := parse([]byte(fixture))
	if len(out) != 2 {
		t.Fatalf("want 2 findings, got %d", len(out))
	}
	byRule := map[string]types.SandboxEmittedFinding{}
	for _, f := range out {
		if f.Tool != "gosec" || f.Title == "" {
			t.Errorf("missing core fields: %+v", f)
		}
		byRule[f.RuleID] = f
	}
	sqli := byRule["gosec::G201"]
	if sqli.Severity != types.SeverityHigh || len(sqli.CWE) != 1 || sqli.CWE[0] != "CWE-89" {
		t.Errorf("high-confidence SQLi should be high + CWE-89, got %+v", sqli)
	}
	if sqli.Endpoint != "/workspace/db.go:42" {
		t.Errorf("endpoint should be file:line, got %q", sqli.Endpoint)
	}
	rng := byRule["gosec::G404"]
	if rng.Severity != types.SeverityMedium {
		t.Errorf("a LOW-confidence high should cap at medium, got %s", rng.Severity)
	}
}

func TestParse_MalformedIsEmpty(t *testing.T) {
	if got := parse([]byte("not json")); got != nil {
		t.Errorf("malformed → no findings, got %+v", got)
	}
}
