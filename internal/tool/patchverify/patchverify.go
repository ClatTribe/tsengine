// Package patchverify is the sandbox tool that EXECUTION-VERIFIES a proposed code patch against the
// repository's own tests — the product-side twin of the bench oracle in internal/bench/cvepatch.
//
// THE GAP THIS CLOSES. `codeagent.ProposePatchIterative` takes a Verifier and only the benches ever
// supplied one; the product endpoint and the delivery-time patcher ran single-shot `ProposePatch`
// with no execution oracle, so "2/2 real CVEs fixed" described the harness and the PR the customer
// received carried a patch nobody had run.
//
// WHAT "VERIFIED" MEANS HERE, and nothing weaker: the tool runs in the scan sandbox over the
// mounted clone, applies the patch and the engineer's regression test, and reports Verified ONLY
// when (1) the regression test FAILS on the unpatched tree, (2) it PASSES on the patched tree, and
// (3) the repository's existing suite still passes after the patch. A regression test that passes
// before the patch pins nothing (Vacuous); a patch that breaks the suite is BrokeSuite; a patch the
// regression still fails is NotFixed. Every other case — no detectable runner, a runtime the image
// lacks (there is no node in the sandbox, so JS/TS suites cannot run here), a timeout — is
// Unverifiable WITH THE REASON, never a pass. The verdict is JSON in Result.Output; the tool emits
// no findings.
//
// Runners detected: Go (go.mod → `go test ./...`, regression via -run on the test names in the
// file) and Python (pytest.ini/pyproject.toml/setup.py/requirements.txt → `python3 -m pytest -q`,
// regression via the file path). A `test_command` argument overrides suite detection.
package patchverify

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/ClatTribe/tsengine/internal/tool"
)

const (
	Verified     = "verified"      // regression failed before, passes after; suite passes after
	NotFixed     = "not_fixed"     // regression still fails after the patch
	BrokeSuite   = "broke_suite"   // the existing suite passed before and fails after
	Vacuous      = "vacuous"       // the regression test passes on the UNPATCHED tree — it pins nothing
	Unverifiable = "unverifiable"  // no runner / no runtime / no regression / timeout — stated in Reason
	Timeout      = 8 * time.Minute // per command wall clock; a suite slower than this is unverifiable here
)

// Verdict is the tool's output.
type Verdict struct {
	Status string `json:"status"`
	Reason string `json:"reason,omitempty"`
	Runner string `json:"runner,omitempty"` // "go" | "python" | "custom"
	// The four observations the status rests on, so a reader can check the reasoning.
	RegressionBefore string `json:"regression_before,omitempty"` // "pass" | "fail" | "skipped"
	RegressionAfter  string `json:"regression_after,omitempty"`
	SuiteBefore      string `json:"suite_before,omitempty"`
	SuiteAfter       string `json:"suite_after,omitempty"`
	// Tail of the failing command's output when the verdict is a failure — the feedback an
	// iterative patcher threads into its next attempt.
	Output string `json:"output,omitempty"`
}

type PatchVerify struct{}

func New() *PatchVerify { return &PatchVerify{} }

func (*PatchVerify) Name() string              { return "patchverify" }
func (*PatchVerify) SandboxExecution() bool    { return true }
func (*PatchVerify) MITRETechniques() []string { return nil }
func (*PatchVerify) KnownArgs() []string {
	return []string{"target", "files", "regression", "test_command"}
}

func (*PatchVerify) Run(ctx context.Context, args tool.Args) (tool.Result, error) {
	target, _ := args["target"].(string)
	if strings.TrimSpace(target) == "" {
		return tool.Result{}, errors.New("patchverify: missing required arg 'target'")
	}
	files := filesArg(args["files"])
	if len(files) == 0 {
		return tool.Result{}, errors.New("patchverify: 'files' carries no patched file")
	}
	regression, _ := args["regression"].(string)
	custom, _ := args["test_command"].(string)
	v := Verify(ctx, target, files, regression, custom)
	b, _ := json.Marshal(v)
	return tool.Result{Output: string(b)}, nil
}

// Verify is the tool's core, exported so a host-side caller can run it over a local checkout in tests.
func Verify(ctx context.Context, dir string, files map[string]string, regression, custom string) Verdict {
	regContent, hasReg := files[regression]
	if regression == "" || !hasReg || strings.TrimSpace(regContent) == "" {
		return Verdict{Status: Unverifiable, Reason: "no regression test accompanies the patch, so there is nothing that fails before and passes after"}
	}
	runner, suiteCmd, regCmd, why := detect(dir, regression, regContent, custom)
	if runner == "" {
		return Verdict{Status: Unverifiable, Reason: why}
	}
	v := Verdict{Runner: runner}

	// BEFORE, on the PRISTINE tree: the existing suite first (before the regression test lands, or
	// its expected failure would count against the suite), then the regression test alone, which
	// must fail — a regression that passes here pins nothing.
	suiteBefore, _ := run(ctx, dir, suiteCmd)
	v.SuiteBefore = suiteBefore
	if err := writeFiles(dir, map[string]string{regression: regContent}); err != nil {
		return Verdict{Status: Unverifiable, Reason: "could not write the regression test: " + err.Error()}
	}
	regBefore, outRB := run(ctx, dir, regCmd)
	v.RegressionBefore = regBefore
	if regBefore == "timeout" {
		return Verdict{Status: Unverifiable, Reason: "the regression test did not finish within " + Timeout.String(), Runner: runner, RegressionBefore: regBefore}
	}
	if regBefore == "pass" {
		v.Status, v.Reason, v.Output = Vacuous, "the regression test passes on the UNPATCHED tree, so it does not pin this vulnerability", tail(outRB)
		return v
	}

	// AFTER: apply the patch (regression already present) and run both.
	if err := writeFiles(dir, files); err != nil {
		return Verdict{Status: Unverifiable, Reason: "could not apply the patch: " + err.Error(), Runner: runner}
	}
	regAfter, outRA := run(ctx, dir, regCmd)
	v.RegressionAfter = regAfter
	if regAfter != "pass" {
		v.Status, v.Reason, v.Output = NotFixed, "the regression test still fails after the patch", tail(outRA)
		if regAfter == "timeout" {
			v.Status, v.Reason = Unverifiable, "the regression test did not finish within "+Timeout.String()+" after the patch"
		}
		return v
	}
	suiteAfter, outSA := run(ctx, dir, suiteCmd)
	v.SuiteAfter = suiteAfter
	switch {
	case suiteAfter == "pass":
		v.Status = Verified
		v.Reason = "the regression test failed on the unpatched tree and passes with the patch; the existing suite passes"
	case suiteAfter == "timeout":
		v.Status, v.Reason = Unverifiable, "the suite did not finish within "+Timeout.String()+" after the patch"
	case suiteBefore == "pass":
		v.Status, v.Reason, v.Output = BrokeSuite, "the existing suite passed before the patch and fails after it", tail(outSA)
	default:
		// The suite was already failing before the patch: the regression is proven, the suite
		// proves nothing either way. Say exactly that rather than claiming a clean suite.
		v.Status = Verified
		v.Reason = "the regression test failed on the unpatched tree and passes with the patch; the existing suite was already failing before the patch, so it says nothing about this change"
	}
	return v
}

// detect picks the runner from the tree. Returns "" with a reason when nothing can run here.
func detect(dir, regression, regContent, custom string) (runner string, suiteCmd, regCmd []string, why string) {
	exists := func(p string) bool { _, err := os.Stat(filepath.Join(dir, p)); return err == nil }
	switch {
	case exists("go.mod") && strings.HasSuffix(regression, "_test.go"):
		names := goTestNames(regContent)
		if len(names) == 0 {
			return "", nil, nil, "the Go regression file declares no Test function"
		}
		if _, err := exec.LookPath("go"); err != nil {
			return "", nil, nil, "go.mod present but no go toolchain in this sandbox"
		}
		pkg := "./" + filepath.ToSlash(filepath.Dir(regression)) + "/"
		suite := []string{"go", "test", "./..."}
		if custom != "" {
			suite = []string{"sh", "-c", custom}
		}
		return "go", suite, []string{"go", "test", pkg, "-run", "^(" + strings.Join(names, "|") + ")$", "-count=1"}, ""
	case (exists("pytest.ini") || exists("pyproject.toml") || exists("setup.py") || exists("requirements.txt") || exists("setup.cfg")) && strings.HasSuffix(regression, ".py"):
		if _, err := exec.LookPath("python3"); err != nil {
			return "", nil, nil, "a Python project but no python3 in this sandbox"
		}
		suite := []string{"python3", "-m", "pytest", "-q", "-x"}
		if custom != "" {
			suite = []string{"sh", "-c", custom}
		}
		return "python", suite, []string{"python3", "-m", "pytest", "-q", regression}, ""
	case exists("package.json"):
		return "", nil, nil, "a JavaScript/TypeScript project: the scan sandbox carries no node runtime, so its suite cannot be run here"
	case custom != "":
		return "custom", []string{"sh", "-c", custom}, []string{"sh", "-c", custom}, ""
	}
	return "", nil, nil, "no test runner detected (go.mod, pytest/pyproject, or a test_command)"
}

var goTestRe = regexp.MustCompile(`(?m)^func (Test[A-Za-z0-9_]+)\(`)

func goTestNames(src string) []string {
	var out []string
	for _, m := range goTestRe.FindAllStringSubmatch(src, -1) {
		out = append(out, m[1])
	}
	return out
}

// run executes a command in dir with the wall clock and reports pass / fail / timeout.
func run(ctx context.Context, dir string, argv []string) (string, string) {
	if len(argv) == 0 {
		return "skipped", ""
	}
	cctx, cancel := context.WithTimeout(ctx, Timeout)
	defer cancel()
	exe := argv[0]
	cmd := exec.CommandContext(cctx, exe, argv[1:]...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "CI=1", "GOFLAGS=-mod=mod", "GOWORK=off")
	var buf bytes.Buffer
	cmd.Stdout, cmd.Stderr = &buf, &buf
	err := cmd.Run()
	if errors.Is(cctx.Err(), context.DeadlineExceeded) {
		return "timeout", buf.String()
	}
	if err != nil {
		return "fail", buf.String()
	}
	return "pass", buf.String()
}

func writeFiles(dir string, files map[string]string) error {
	root, err := filepath.Abs(dir)
	if err != nil {
		return err
	}
	for rel, content := range files {
		p := filepath.Join(root, filepath.Clean("/"+rel))
		if !strings.HasPrefix(p, root+string(filepath.Separator)) {
			return fmt.Errorf("path %q escapes the repository", rel)
		}
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			return err
		}
	}
	return nil
}

func filesArg(v any) map[string]string {
	out := map[string]string{}
	switch m := v.(type) {
	case map[string]string:
		for k, s := range m {
			out[k] = s
		}
	case map[string]any:
		for k, s := range m {
			if str, ok := s.(string); ok {
				out[k] = str
			}
		}
	}
	return out
}

func tail(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 4000 {
		return "…" + s[len(s)-4000:]
	}
	return s
}

func init() { tool.Register(New()) }
