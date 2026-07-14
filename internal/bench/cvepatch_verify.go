package bench

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/ClatTribe/tsengine/internal/codeagent"
)

// cvepatch_verify.go is the EXECUTION ORACLE that disposes the `fixed` verdict — the "deterministic
// verifier disposes" half the product promises (§10, retest.Verify parity). It applies the engineer's
// proposed patch, runs the instance's REAL exploit PoC + a regression check, and sets fixed=FIXED only
// when the exploit is BLOCKED *and* legit behaviour still works. Disk-light (a temp dir + the single
// patched file + the runtime; no 200GB rebuild). Grounded + overfit-free (§14.2): the PoC/regression
// live in the INSTANCE data (external, per-CVE), NOT in this scoring code — this file has no per-CVE
// logic. The engineer can never mark its own fix working: the oracle, not the model, decides.

// VerifySpec is an instance's execution oracle (external data — the real CVE's exploit + a regression
// check). Absent → the instance stays JudgeUnknown (honest: no oracle, no verdict).
type VerifySpec struct {
	Runtime  string            `json:"runtime"`   // "node" | "python3"
	AuxFiles map[string]string `json:"aux_files"` // path→content: dep stubs the driver needs (e.g. a node_modules shim)
	Driver   string            `json:"driver"`    // driver script: require the patched module, run exploit+regression, print exactly "FIXED" or "NOT_FIXED"
	Ext      string            `json:"ext"`       // driver file extension ("js"|"py")
}

// runtimeAvailable reports whether the spec's runtime binary is on PATH (the honest gate — no runtime
// → the oracle can't run → the caller keeps JudgeUnknown, never a fabricated verdict).
func runtimeAvailable(rt string) bool {
	if rt == "" {
		return false
	}
	_, err := exec.LookPath(rt)
	return err == nil
}

// VerifyPatch writes the patched file(s) + aux files + driver into a temp dir, runs the driver, and
// returns FIXED only if it prints "FIXED". Any failure (build/run error, "NOT_FIXED", missing runtime)
// → NotFixed/Unknown, never a false positive. The patched files come from the engineer's own rewrite.
func VerifyPatch(ctx context.Context, patch codeagent.Patch, spec *VerifySpec) Judged {
	j, _ := verifyPatch(ctx, patch, spec)
	return j
}

// verifyPatch is the shared implementation; it also returns the driver's raw output so the iterative
// refine loop can thread WHY a patch failed back into the next attempt.
func verifyPatch(ctx context.Context, patch codeagent.Patch, spec *VerifySpec) (Judged, string) {
	if spec == nil || !runtimeAvailable(spec.Runtime) {
		return JudgeUnknown, ""
	}
	if patch.Empty() {
		return JudgeNotFixed, "the engineer produced no patch" // no patch can't have fixed anything
	}
	dir, err := os.MkdirTemp("", "cvepatch-verify-*")
	if err != nil {
		return JudgeUnknown, ""
	}
	defer os.RemoveAll(dir)

	write := func(rel, content string) error {
		p := filepath.Join(dir, filepath.Clean(rel))
		if !strings.HasPrefix(p, dir) { // defence-in-depth: no escape from the temp dir
			return os.ErrPermission
		}
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			return err
		}
		return os.WriteFile(p, []byte(content), 0o600)
	}
	// the engineer's patched file(s) — the thing under test
	for _, f := range patch.Files {
		if err := write(f.Path, f.Content); err != nil {
			return JudgeUnknown, ""
		}
	}
	// aux files the driver needs (dep stubs, fixtures — external instance data)
	for rel, content := range spec.AuxFiles {
		if err := write(rel, content); err != nil {
			return JudgeUnknown, ""
		}
	}
	ext := spec.Ext
	if ext == "" {
		ext = "js"
	}
	driver := "__verify_driver." + ext
	if err := write(driver, spec.Driver); err != nil {
		return JudgeUnknown, ""
	}
	//nolint:gosec // by design: the benchmark runs the operator-provided runtime (node/python3) on the
	// instance's PoC driver — that IS the execution oracle. Runtime is gated to a PATH-resolved binary.
	cmd := exec.CommandContext(ctx, spec.Runtime, filepath.Join(dir, driver))
	cmd.Dir = dir
	out, _ := cmd.CombinedOutput() // a non-zero exit is a NOT_FIXED signal, not a harness error
	if strings.Contains(string(out), "FIXED") && !strings.Contains(string(out), "NOT_FIXED") {
		return JudgeFixed, ""
	}
	return JudgeNotFixed, strings.TrimSpace(string(out))
}

// Verifier adapts the execution oracle to codeagent's Verifier callback, so ProposePatchIterative can
// dispose each attempt and thread the driver's real output back on failure.
func (spec *VerifySpec) Verifier() codeagent.Verifier {
	return func(ctx context.Context, p codeagent.Patch) codeagent.VerifyOutcome {
		j, feedback := verifyPatch(ctx, p, spec)
		return codeagent.VerifyOutcome{Fixed: j == JudgeFixed, Feedback: feedback}
	}
}
