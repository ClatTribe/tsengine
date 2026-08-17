package webagent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// requiredIndicator is the grounding gate: record_finding accepts a vuln class only if a cited turn
// carries one of the deterministic indicators listed for it. That gate is only as good as the promise
// that some TOOL actually emits each of those indicators — if a class lists an indicator no tool ever
// sets (a typo, or an emitter deleted in a refactor), the class becomes permanently unrecordable: the
// agent can exploit it but record_finding rejects every attempt, and the capture silently vanishes.
//
// Nothing enforced that promise; the map is maintained by hand across ~15 tool files. This proves,
// structurally, that every indicator the gate REQUIRES is one the package actually PRODUCES — by
// finding the literal in a non-test source file other than the gate's own. It is the webagent twin of
// the registry→EscalationPlanner seam guard: a silent capability gap turned into a loud test failure.
func TestEveryRequiredIndicatorIsEmittedBySomeTool(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	// The corpus of source that could EMIT an indicator: every non-test .go file except tools.go,
	// which holds the requiredIndicator map itself (so a value only appearing there does NOT count as
	// emitted — that is exactly the drift we want to catch).
	var corpus strings.Builder
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") || f == "tools.go" {
			continue
		}
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		corpus.Write(b)
		corpus.WriteByte('\n')
	}
	src := corpus.String()

	// Collect the distinct required indicators, then assert each appears as a quoted literal in the
	// emitter corpus.
	seen := map[string]bool{}
	for class, inds := range requiredIndicator {
		for _, ind := range inds {
			if seen[ind] {
				continue
			}
			seen[ind] = true
			// Mirror the RUNTIME match (hasIndicator uses strings.HasPrefix), so an indicator emitted
			// with a colon-suffixed detail — e.g. `"external_redirect:"+host` — still counts as
			// emitted, exactly as it grounds a finding at runtime.
			if !strings.Contains(src, `"`+ind+`"`) && !strings.Contains(src, `"`+ind+`:`) {
				t.Errorf("indicator %q (required by class %q and others) is emitted by NO tool — "+
					"record_finding will reject every attempt to record that class, so the exploit "+
					"works but the capture silently vanishes. Add the emitter, or fix the indicator name.",
					ind, class)
			}
		}
	}
}
