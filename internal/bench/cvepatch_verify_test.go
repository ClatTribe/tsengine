package bench

import (
	"context"
	"os/exec"
	"testing"

	"github.com/ClatTribe/tsengine/internal/codeagent"
)

// TestVerifyPatch_GatesWithoutRuntime: no spec or a missing runtime → JudgeUnknown, never a fabricated
// verdict (the honest gate).
func TestVerifyPatch_GatesWithoutRuntime(t *testing.T) {
	p := codeagent.Patch{Files: []codeagent.PatchedFile{{Path: "m.js", Content: "x"}}}
	if got := VerifyPatch(context.Background(), p, nil); got != JudgeUnknown {
		t.Errorf("nil spec: want unknown, got %s", got)
	}
	spec := &VerifySpec{Runtime: "definitely-not-a-real-binary-xyz", Driver: "print('FIXED')"}
	if got := VerifyPatch(context.Background(), p, spec); got != JudgeUnknown {
		t.Errorf("missing runtime: want unknown, got %s", got)
	}
}

// TestVerifyPatch_ExecutesPoC runs a real node PoC: a FIXED patch (guards __proto__) blocks the
// exploit; a NON-fix patch does not. Skips if node isn't installed.
func TestVerifyPatch_ExecutesPoC(t *testing.T) {
	if _, err := exec.LookPath("node"); err != nil {
		t.Skip("node not installed — execution oracle skipped")
	}
	driver := `
const m = require('./m.js');
m.set({}, '__proto__.polluted', 'YES');
const o = {}; m.set(o, 'a', 'b');
if (({}).polluted === undefined && o.a === 'b') console.log('FIXED');
else console.log('NOT_FIXED');
`
	spec := &VerifySpec{Runtime: "node", Ext: "js", Driver: driver}

	fixed := codeagent.Patch{Files: []codeagent.PatchedFile{{Path: "m.js", Content: `
module.exports = { set(o, k, v) { if (k === '__proto__') return o; o[k] = v; return o; } };`}}}
	if got := VerifyPatch(context.Background(), fixed, spec); got != JudgeFixed {
		t.Errorf("guarded patch: want FIXED, got %s", got)
	}

	notFixed := codeagent.Patch{Files: []codeagent.PatchedFile{{Path: "m.js", Content: `
module.exports = { set(o, k, v) { const p=k.split('.'); let cur=o; for(let i=0;i<p.length-1;i++){ if(!cur[p[i]])cur[p[i]]={}; cur=cur[p[i]]; } cur[p[p.length-1]]=v; return o; } };`}}}
	if got := VerifyPatch(context.Background(), notFixed, spec); got != JudgeNotFixed {
		t.Errorf("unguarded patch: want NOT_FIXED, got %s", got)
	}
}
