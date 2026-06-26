package apkid

import (
	"testing"

	"github.com/ClatTribe/tsengine/pkg/types"
)

// A realistic APKiD -j report: a packer + anti-debug + an (informational) compiler match. The packer and
// anti-debug become findings (with the right severities); the compiler is informational and must NOT.
const fixture = `{
  "apkid_version": "2.1.5",
  "files": [
    {"filename": "classes.dex", "matches": {
      "compiler": ["r8"],
      "packer": ["Jiagu"],
      "anti_debug": ["Debug.isDebuggerConnected() check"]
    }}
  ]
}`

func TestParse_FlagsPackerAndAntiAnalysisNotCompiler(t *testing.T) {
	out := parse([]byte(fixture))
	byRule := map[string]types.SandboxEmittedFinding{}
	for _, f := range out {
		byRule[f.RuleID] = f
	}
	if p, ok := byRule["apkid::packer"]; !ok || p.Severity != types.SeverityMedium {
		t.Errorf("a packer should be a medium finding, got %+v", p)
	}
	if a, ok := byRule["apkid::anti_debug"]; !ok || a.Severity != types.SeverityInfo {
		t.Errorf("anti-debug should be an info finding, got %+v", a)
	}
	if _, ok := byRule["apkid::compiler"]; ok {
		t.Error("the compiler match is informational and must NOT become a finding")
	}
	if len(out) != 2 {
		t.Errorf("want exactly 2 findings (packer + anti_debug), got %d: %+v", len(out), out)
	}
	for _, f := range out {
		if f.Tool != "apkid" || f.Endpoint != "classes.dex" || f.Title == "" {
			t.Errorf("finding missing core fields: %+v", f)
		}
	}
}

// Malformed JSON → no findings, no panic (best-effort, like the other wrappers).
func TestParse_MalformedIsEmpty(t *testing.T) {
	if got := parse([]byte("not json")); got != nil {
		t.Errorf("malformed output should yield no findings, got %+v", got)
	}
}
