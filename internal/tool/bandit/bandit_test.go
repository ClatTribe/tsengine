package bandit

import (
	"testing"

	"github.com/ClatTribe/tsengine/pkg/types"
)

// A representative bandit -f json run: a high-confidence shell-injection (B602, CWE-78 → high), and a
// LOW-confidence high (B303 weak MD5) that must cap at medium (bandit's low-confidence highs are FP-prone).
const fixture = `{
  "results": [
    {"filename":"/workspace/app.py","issue_severity":"HIGH","issue_confidence":"HIGH","issue_cwe":{"id":78},"issue_text":"subprocess call with shell=True identified","test_id":"B602","line_number":42},
    {"filename":"/workspace/crypto.py","issue_severity":"HIGH","issue_confidence":"LOW","issue_cwe":{"id":327},"issue_text":"Use of insecure MD5 hash function","test_id":"B303","line_number":9}
  ],
  "metrics": {}
}`

func TestParse_MapsSeverityCWEAndCapsLowConfidence(t *testing.T) {
	out := parse([]byte(fixture))
	if len(out) != 2 {
		t.Fatalf("want 2 findings, got %d", len(out))
	}
	byRule := map[string]types.SandboxEmittedFinding{}
	for _, f := range out {
		if f.Tool != "bandit" || f.Title == "" {
			t.Errorf("missing core fields: %+v", f)
		}
		byRule[f.RuleID] = f
	}
	sh := byRule["bandit::B602"]
	if sh.Severity != types.SeverityHigh || len(sh.CWE) != 1 || sh.CWE[0] != "CWE-78" {
		t.Errorf("high-confidence shell injection should be high + CWE-78, got %+v", sh)
	}
	if sh.Endpoint != "/workspace/app.py:42" {
		t.Errorf("endpoint should be file:line, got %q", sh.Endpoint)
	}
	md5 := byRule["bandit::B303"]
	if md5.Severity != types.SeverityMedium {
		t.Errorf("a LOW-confidence high should cap at medium, got %s", md5.Severity)
	}
}

func TestParse_MalformedIsEmpty(t *testing.T) {
	if got := parse([]byte("not json")); got != nil {
		t.Errorf("malformed → no findings, got %+v", got)
	}
}
