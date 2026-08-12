package bench

import (
	"context"
	"encoding/json"
	"os"
	"testing"

	"github.com/ClatTribe/tsengine/internal/codeagent"
)

// CAN THE GRADER SAY NO?
//
// T4's score rests entirely on VerifyPatch: it runs the exploit and a regression against the model's
// patch and returns fixed / not_fixed / unknown. Every observed run has returned `fixed` or `unknown`
// — a `not_fixed` has never actually been seen. A grader that has only ever said yes is
// indistinguishable, from the outside, from one that cannot say no, and in that case T4's number is
// not a measurement of anything.
//
// This settles it by handing the oracle a patch that certainly does NOT fix the vulnerability: the
// ORIGINAL vulnerable file, unchanged. If that is graded `fixed`, the execution oracle is broken and
// every T4 score is meaningless. The gold patch is run through the same path as the control, because a
// grader that says no to everything is equally useless.
//
// It also means an LLM that learns to emit the input unchanged cannot score.

func loadSeeds(t *testing.T) []CVEPatchInstance {
	t.Helper()
	b, err := os.ReadFile("../../fixtures/cvepatch/seed.json")
	if err != nil {
		t.Skipf("seed dataset not present: %v", err)
	}
	var seeds []CVEPatchInstance
	if err := json.Unmarshal(b, &seeds); err != nil {
		var wrapper struct {
			Instances []CVEPatchInstance `json:"instances"`
		}
		if err2 := json.Unmarshal(b, &wrapper); err2 != nil {
			t.Fatalf("parse seed.json: %v / %v", err, err2)
		}
		seeds = wrapper.Instances
	}
	return seeds
}

func patchFrom(files []VFile) codeagent.Patch {
	p := codeagent.Patch{}
	for _, f := range files {
		p.Files = append(p.Files, codeagent.PatchedFile{Path: f.Path, Content: f.Content})
	}
	return p
}

// THE ONE THAT MATTERS. The unchanged vulnerable file must NOT be graded fixed.
func TestT4Oracle_RejectsAnUnfixedPatch(t *testing.T) {
	ctx := context.Background()
	checked := 0
	for _, in := range loadSeeds(t) {
		if in.Verify == nil || len(in.VulnFiles) == 0 {
			continue
		}
		got := VerifyPatch(ctx, patchFrom(in.VulnFiles), in.Verify)
		if got == JudgeUnknown {
			continue // runtime absent — the honest gate, not a grader failure
		}
		checked++
		if got == JudgeFixed {
			t.Errorf("ORACLE BROKEN [%s]: the UNCHANGED vulnerable file was graded %q. Every T4 score "+
				"rests on this verdict, so a grader that cannot say no makes the whole number "+
				"meaningless — and a model that echoed its input would score full marks.", in.ID, got)
		}
	}
	if checked == 0 {
		t.Skip("no instance had a runnable oracle (node/python3 absent) — nothing verified")
	}
	t.Logf("oracle correctly refused %d unfixed patch(es)", checked)
}

// THE POSITIVE DIRECTION is not asserted here, deliberately. The seeds carry gold_files as PATHS (the
// localization oracle) and not fixed CONTENT, so a gold patch cannot be assembled from the fixtures —
// and writing one myself would just be testing my own idea of the fix.
//
// It does not need asserting: the real `tsbench cvepatch` runs have repeatedly graded model-produced
// patches `fixed`, which is the yes-direction evidence. Both directions are therefore covered — the no
// by this test, the yes by the runs — and the gap was only ever that nobody had checked the no.
